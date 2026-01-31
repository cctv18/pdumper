// SPDX-License-Identifier: GPL-2.0
/*
 * Physical Dump Helper for Android Pstore
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/kmsg_dump.h>
#include <linux/bootconfig.h>
#include <linux/of.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <linux/phy/phy-dump.h>

#ifdef CONFIG_PSTORE_BLK

#define PSTORE_TARGET_SIZE   (4 * 1024 * 1024)
#define AVB_SAFETY_MARGIN    (512 * 1024)
#define SECTOR_SHIFT         9

static DECLARE_COMPLETION(phy_dump_done);

struct pstore_hijack_ctx {
	struct block_device *bdev;
	struct file *file;
	void *holder;
	sector_t start_sector;
	bool active;
};

static struct pstore_hijack_ctx g_hijack = {0};
extern char *saved_command_line;

/* ================== 兼容性层 ================== */
static int compat_open_bdev(const char *path, struct pstore_hijack_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	struct file *f = bdev_file_open_by_path(path, BLK_OPEN_READ | BLK_OPEN_WRITE, ctx, NULL);
	if (IS_ERR(f)) return PTR_ERR(f);
	ctx->file = f;
	ctx->bdev = file_bdev(f);
#else
	struct block_device *bdev = blkdev_get_by_path(path, FMODE_READ | FMODE_WRITE, ctx, NULL);
	if (IS_ERR(bdev)) return PTR_ERR(bdev);
	ctx->bdev = bdev;
	ctx->holder = ctx;
#endif
	return 0;
}

static void compat_close_bdev(struct pstore_hijack_ctx *ctx)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	if (ctx->file) fput(ctx->file);
#else
	if (ctx->bdev) blkdev_put(ctx->bdev, ctx->holder);
#endif
	ctx->bdev = NULL;
	ctx->active = false;
}

/* ================== 分区探测逻辑 ================== */
/* 1. 从 Bootconfig (XBC) 获取 - [针对 Android 12+ GKI] */
static const char * __init get_suffix_from_bootconfig(void)
{
	struct xbc_node *node;
	const char *val;

	/* 查找 androidboot.slot_suffix (你的机型里是这个) */
	node = xbc_find_node("androidboot.slot_suffix");
	if (node) {
		val = xbc_node_get_data(node);
		if (val) return val;
	}

	/* 查找 androidboot.slot (兼容写法) */
	node = xbc_find_node("androidboot.slot");
	if (node) {
		val = xbc_node_get_data(node);
		if (val) return val;
	}

	return NULL;
}

/* 2. 从 Device Tree /chosen/bootargs 获取 - [针对 Bootloader 传递方式差异] */
static const char * __init get_suffix_from_dt_chosen(void)
{
	struct device_node *np;
	const char *bootargs = NULL;
	const char *ret = NULL;

	np = of_find_node_by_path("/chosen");
	if (!np) return NULL;

	if (of_property_read_string(np, "bootargs", &bootargs) == 0 && bootargs) {
		if (strstr(bootargs, "androidboot.slot_suffix=_a") || 
			strstr(bootargs, "androidboot.slot=_a")) {
			ret = "_a";
		} else if (strstr(bootargs, "androidboot.slot_suffix=_b") || 
				   strstr(bootargs, "androidboot.slot=_b")) {
			ret = "_b";
		}
	}
	of_node_put(np);
	return ret;
}

/* 3. 从 Qualcomm 专有 DT 节点获取 - [针对旧高通平台] */
static const char * __init get_suffix_from_dt_firmware(void)
{
	struct device_node *np;
	const char *suffix = NULL;

	np = of_find_node_by_path("/firmware/android");
	if (np) {
		of_property_read_string(np, "slot_suffix", &suffix);
		of_node_put(np);
	}
	return suffix;
}

/* [主函数] 综合获取非活动槽位后缀 */
static const char * __init get_inactive_suffix(void)
{
	const char *active_suffix = NULL;
	const char *source = "unknown";

	/* 优先级 1: Bootconfig (你的机型验证通过) */
	active_suffix = get_suffix_from_bootconfig();
	if (active_suffix) {
		source = "bootconfig";
		goto found;
	}

	/* 优先级 2: Kernel Command Line (传统) */
	if (saved_command_line) {
		if (strstr(saved_command_line, "androidboot.slot_suffix=_a") || 
			strstr(saved_command_line, "androidboot.slot=_a")) {
			active_suffix = "_a";
			source = "cmdline";
			goto found;
		}
		if (strstr(saved_command_line, "androidboot.slot_suffix=_b") || 
			strstr(saved_command_line, "androidboot.slot=_b")) {
			active_suffix = "_b";
			source = "cmdline";
			goto found;
		}
	}

	/* 优先级 3: Device Tree /chosen */
	active_suffix = get_suffix_from_dt_chosen();
	if (active_suffix) {
		source = "dt_chosen";
		goto found;
	}

	/* 优先级 4: Device Tree /firmware/android */
	active_suffix = get_suffix_from_dt_firmware();
	if (active_suffix) {
		source = "dt_firmware";
		goto found;
	}

	return NULL;

found:
	/* 打印详细日志，确认来源 */
	pr_info("Active slot '%s' found via %s\n", active_suffix, source);
	
	/* 去除可能存在的引号 (bootconfig 有时会带引号) */
	if (strstr(active_suffix, "_a")) return "_b";
	if (strstr(active_suffix, "_b")) return "_a";
	
	pr_warn("Unknown slot format: %s\n", active_suffix);
	return NULL;
}

static int __init try_hijack_partition(const char *base_name, const char *suffix, char *out_path, size_t path_len)
{
	char path[128];
	int ret;
	sector_t capacity, needed;
	char target_name[64];
	int retries = 50; /* [修改点] 设置重试次数：50次 * 100ms = 5秒超时 */

	/* 优先使用 PARTLABEL (内核级查找，无需 /dev 链接) */
	if (suffix)
		snprintf(path, sizeof(path), "PARTLABEL=%s%s", base_name, suffix);
	else
		snprintf(path, sizeof(path), "PARTLABEL=%s", base_name);

	/* 构造 PARTLABEL 路径 */
	snprintf(path, sizeof(path), "PARTLABEL=%s", target_name);
	pr_info("Probing %s (Waiting for UFS Driver up to 5s)...\n", path);
	
	/* 循环等待UFS逻辑 */
	while (retries > 0) {
		ret = compat_open_bdev(path, &g_hijack);
		if (ret == 0) {
			/* 成功打开，跳出循环 */
			break;
		}
		
		/* 如果是 -ENODEV (设备未找到)，等待 100ms 后重试 */
		if (ret == -ENODEV || ret == -ENOENT) {
			msleep(100); 
			retries--;
			continue;
		}

		/* 其他错误（如权限不足），直接失败 */
		break;
	}
	
	ret = compat_open_bdev(path, &g_hijack);
	if (ret) {
		/* 回退到 /dev 路径 (Late init 可能会用到) */
		if (suffix)
			snprintf(path, sizeof(path), "/dev/block/by-name/%s%s", base_name, suffix);
		else
			snprintf(path, sizeof(path), "/dev/block/by-name/%s", base_name);
		
		pr_info("PARTLABEL failed, fallback to %s ...\n", path);
		ret = compat_open_bdev(path, &g_hijack);
		if (ret) {
			pr_info("Failed to open %s (err=%d)\n", path, ret);
			return ret;
		}
	}

	capacity = bdev_nr_sectors(g_hijack.bdev);
	needed = (PSTORE_TARGET_SIZE + AVB_SAFETY_MARGIN) >> SECTOR_SHIFT;

	if (capacity <= needed) {
		pr_warn("Target %s too small: %llu sectors < %llu needed\n", path, capacity, needed);
		compat_close_bdev(&g_hijack);
		return -ENOSPC;
	}

	g_hijack.start_sector = capacity - needed;
	g_hijack.active = true;

	if (out_path) strscpy(out_path, path, path_len);
	pr_info("HIJACK SUCCESS -> %s\n", path);
	pr_info("Dump Area: Start Sector %llu, Size 4MB (Safety Margin 512KB)\n", g_hijack.start_sector);
	return 0;
}

/* 供内核模块加载子系统调用的等待函数 */
void phy_dump_wait_for_ready(void)
{
    /* 等待初始化完成，不设置超时（因为必须等 UFS 好了才能加载模块） */
    wait_for_completion(&phy_dump_done);
}
EXPORT_SYMBOL_GPL(phy_dump_wait_for_ready);

/* * 优先探测的 Raw 分区列表 
 * 这些通常是厂商预留的调试分区，不带 A/B 后缀，且尾部无重要元数据，最适合覆盖写入。
 */
static const char *const priority_raw_partitions[] = {
	"logdump",
	"rawdump",
	"logfs",
	"oplusreserve1",
	"oplusreserve3",
	"oplusreserve4",
	"oplusreserve5",
};

void __init phy_dump_init_hijack(char *blkdev_buf, size_t buf_len)
{
	int i;

	/* 策略 1: 优先尝试专用的 Raw Dump 分区 (非 A/B) */
	pr_info("Scanning priority raw partitions...\n");
	for (i = 0; i < ARRAY_SIZE(priority_raw_partitions); i++) {
		/* 传入 NULL 后缀，直接匹配分区名 */
		if (try_hijack_partition(priority_raw_partitions[i], NULL, blkdev_buf, buf_len) == 0)
			goto out;
	}
	pr_info("Scan for all priority raw partitions failed, trying inactive slot partitions...\n");
	
	/* 策略 2: 尝试 A/B 机型的非活动槽位 */
	const char *suffix = get_inactive_suffix();
	pr_info("Targeting Inactive Slot: %s\n", suffix);
	pr_info("Initializing... Slot Suffix: %s\n", suffix ? suffix : "(none)");
	if (suffix) {
		pr_info("Targeting Inactive Slot: %s\n", suffix);
		if (try_hijack_partition("boot", suffix, blkdev_buf, buf_len) == 0) goto out;
		if (try_hijack_partition("dtbo", suffix, blkdev_buf, buf_len) == 0) goto out;
		if (try_hijack_partition("init_boot", suffix, blkdev_buf, buf_len) == 0) goto out;
		if (try_hijack_partition("cache", suffix, blkdev_buf, buf_len) == 0) goto out;
	} else {
		pr_warn("No A/B slot detected via Bootconfig/DT/Cmdline.\n");
	}
	
	/* 策略 3: 最后尝试通用 Cache 分区 */
	pr_info("Falling back to generic cache...\n");
	if (try_hijack_partition("cache", NULL, blkdev_buf, buf_len) == 0) goto out;

	pr_err("ALL HIJACK ATTEMPTS FAILED. Physical dump disabled.\n");
out:
	/* [新增] 无论成功还是失败，标记初始化已完成，放行模块加载 */
	complete_all(&phy_dump_done);
}

void phy_dump_exit_hijack(void)
{
	if (g_hijack.active) {
		compat_close_bdev(&g_hijack);
		pr_info("Hijack released.\n");
	}
}
EXPORT_SYMBOL_GPL(phy_dump_exit_hijack);

/* ================== Panic Hook ================== */

/* 在 panic() 调用 smp_send_stop() 之前调用此函数 */
void phy_dump_panic_pre_stop(void)
{
	if (g_hijack.active && oops_in_progress) {
		pr_emerg("PANIC DETECTED! Triggering early kmsg_dump before SMP stop...\n");
		/* * 触发标准的 kmsg_dump，这会回调 pstore 的 write 接口。
		 * 由于我们已经在下面 phy_dump_write 中实现了 Bypass VFS 逻辑，
		 * 这将直接导致数据通过 RAW BIO 写入磁盘。
		 */
		kmsg_dump(KMSG_DUMP_PANIC);
	}
}
EXPORT_SYMBOL_GPL(phy_dump_panic_pre_stop);

/* ================== 读写逻辑 ================== */

ssize_t phy_dump_read(struct file *file, char *buf, size_t bytes, loff_t pos)
{
	loff_t hijacked_pos = pos;
	
	/* 逻辑：如果劫持激活，叠加物理偏移 */
	if (g_hijack.active) {
		hijacked_pos += (g_hijack.start_sector << SECTOR_SHIFT);
		/* 仅在读取头部时输出日志，验证系统是否识别到了转储日志 */
		if (pos == 0)
			pr_info("System reading dump header at phys sector %llu (size %zu)\n", 
				(u64)(g_hijack.start_sector), bytes);
	}
	
	/* 无论是否劫持，最终都调用 kernel_read。
	 * 如果没劫持，target_pos == pos，行为与原 blk.c 一致。
	 */
	return kernel_read(file, buf, bytes, &hijacked_pos);
}
EXPORT_SYMBOL_GPL(phy_dump_read);

static int submit_raw_bio(int op, sector_t sector, void *data, size_t len)
{
	struct bio *bio;
	struct page *page;
	
	if (!g_hijack.bdev) return -ENODEV;

	bio = bio_alloc(g_hijack.bdev, 1, op | REQ_SYNC | REQ_META | REQ_PRIO, GFP_ATOMIC);
	if (!bio) {
		pr_emerg("Failed to allocate atomic BIO for sector %llu\n", (u64)sector);
		return -ENOMEM;
	}

	bio->bi_iter.bi_sector = sector;

	if (data) {
		if (is_vmalloc_addr(data))
			page = vmalloc_to_page(data);
		else
			page = virt_to_page(data);
		if (bio_add_page(bio, page, len, offset_in_page(data)) != len) {
			pr_emerg("BIO add page failed for len %zu\n", len);
			bio_put(bio);
			return -EIO;
		}
	}
	submit_bio(bio); /* 触发 UFS轮询 */
	return 0;
}

static void psblk_panic_wipe_header(void)
{
	static char zero_buf[4096] = {0}; 
	pr_emerg("Wiping dump header at sector %llu...\n", (u64)g_hijack.start_sector);
	submit_raw_bio(REQ_OP_WRITE, g_hijack.start_sector, zero_buf, 4096);
}

ssize_t phy_dump_write(struct file *file, const char *buf, size_t bytes, loff_t pos)
{
	/* 逻辑 1: Panic / 中断上下文 -> 必须走 RAW BIO */
	if (in_interrupt() || irqs_disabled() || oops_in_progress) {
		if (g_hijack.active) {
			sector_t phys_sector = g_hijack.start_sector + (pos >> SECTOR_SHIFT);
			if (pos == 0) {
				pr_emerg("Panic write started. Target: Sector %llu\n", (u64)phys_sector);
				psblk_panic_wipe_header();
			}
			if (submit_raw_bio(REQ_OP_WRITE, phys_sector, (void *)buf, bytes) == 0) {
				/* 调试日志：仅在写入非0偏移或特定大小时输出，避免过多刷屏 */
				if (pos == 0 || pos % (1024*1024) == 0)
					pr_emerg("Wrote %zu bytes to sector %llu\n", bytes, (u64)phys_sector);
				return bytes;
			}
			pr_emerg("Raw write failed at sector %llu\n", (u64)phys_sector);
		}
		return -EBUSY; /* 劫持失败且在中断中，无法写入 */
	}

	/* 逻辑 2: 正常上下文 -> 走 VFS */
	loff_t hijacked_pos = pos;
	if (g_hijack.active) {
		hijacked_pos += (g_hijack.start_sector << SECTOR_SHIFT);
	}
	
	/* 回退到 kernel_write，保持与原 blk.c 一致 */
	return kernel_write(file, buf, bytes, &hijacked_pos);
}
EXPORT_SYMBOL_GPL(phy_dump_write);

#endif /* CONFIG_PSTORE_BLK */
