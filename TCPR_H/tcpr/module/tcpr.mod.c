#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xa8c16cf3, "module_layout" },
	{ 0x23a857f5, "xt_unregister_target" },
	{ 0x352091e6, "kmalloc_caches" },
	{ 0xadaabe1b, "pv_lock_ops" },
	{ 0xd98b3288, "ip_local_out" },
	{ 0xc01cf848, "_raw_read_lock" },
	{ 0x27e1a049, "printk" },
	{ 0xb4390f9a, "mcount" },
	{ 0x7f658e80, "_raw_write_lock" },
	{ 0x5258a9bd, "ip_route_me_harder" },
	{ 0x21cbe30b, "xt_register_target" },
	{ 0x2dcf5a98, "__alloc_skb" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x6ad0f196, "kfree_skb" },
	{ 0x783c7933, "kmem_cache_alloc_trace" },
	{ 0xd52bf1ce, "_raw_spin_lock" },
	{ 0xf6ebc03b, "net_ratelimit" },
	{ 0x37a0cba, "kfree" },
	{ 0x69acdf38, "memcpy" },
	{ 0xcd4732ff, "skb_make_writable" },
	{ 0xe113bbbc, "csum_partial" },
	{ 0x128077ac, "skb_put" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=x_tables";


MODULE_INFO(srcversion, "59943CAE7750BF06C2BE845");
