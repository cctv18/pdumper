/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PHY_DUMP_H
#define _LINUX_PHY_DUMP_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/kconfig.h>

#ifdef CONFIG_PSTORE_BLK

/* 初始化劫持逻辑 (PARTLABEL & Path探测) */
void phy_dump_init_hijack(char *blkdev_buf, size_t buf_len);
/* 退出时的资源释放 */
void phy_dump_exit_hijack(void);
/* 等待 Pstore 初始化完成的栅栏函数 */
void phy_dump_wait_for_ready(void);

/* 劫持后的读写接口 */
ssize_t phy_dump_read(struct file *file, char *buf, size_t bytes, loff_t pos);
ssize_t phy_dump_write(struct file *file, const char *buf, size_t bytes, loff_t pos);

/* Panic Hook: 在 SMP 停止前强行触发 Dump */
void phy_dump_panic_pre_stop(void);

#else /* !CONFIG_PSTORE_BLK */

static inline void phy_dump_init_hijack(char *blkdev_buf, size_t buf_len) {}
static inline void phy_dump_exit_hijack(void) {}
static inline void phy_dump_wait_for_ready(void) {}
static inline ssize_t phy_dump_read(struct file *file, char *buf, size_t bytes, loff_t pos) { return -ENODEV; }
static inline ssize_t phy_dump_write(struct file *file, const char *buf, size_t bytes, loff_t pos) { return -ENODEV; }
static inline void phy_dump_panic_pre_stop(void) {}

#endif /* CONFIG_PSTORE_BLK */

#endif /* _LINUX_PHY_DUMP_H */
