#ifndef KSU_SUSFS_DEF_H
#define KSU_SUSFS_DEF_H

#include <linux/bits.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/cred.h>

/********/
/* ENUM */
/********/
/* shared with userspace ksu_susfs tool */
#define SUSFS_MAGIC 0xFAFAFAFA
#define CMD_SUSFS_ADD_SUS_PATH 0x55550
#define CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH 0x55551 /* deprecated */
#define CMD_SUSFS_SET_SDCARD_ROOT_PATH 0x55552 /* deprecated */
#define CMD_SUSFS_ADD_SUS_PATH_LOOP 0x55553
#define CMD_SUSFS_ADD_SUS_MOUNT 0x55560 /* deprecated */
#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS 0x55561
#define CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE 0x55562 /* deprecated */
#define CMD_SUSFS_ADD_SUS_KSTAT 0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT 0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY 0x55572
#define CMD_SUSFS_ADD_TRY_UMOUNT 0x55580 /* deprecated */
#define CMD_SUSFS_SET_UNAME 0x55590
#define CMD_SUSFS_ENABLE_LOG 0x555a0
#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG 0x555b0
#define CMD_SUSFS_ADD_OPEN_REDIRECT 0x555c0
#define CMD_SUSFS_SHOW_VERSION 0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES 0x555e2
#define CMD_SUSFS_SHOW_VARIANT 0x555e3
#define CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE 0x555e4 /* deprecated */
#define CMD_SUSFS_IS_SUS_SU_READY 0x555f0 /* deprecated */
#define CMD_SUSFS_SUS_SU 0x60000 /* deprecated */
#define CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING 0x60010
#define CMD_SUSFS_ADD_SUS_MAP 0x60020
#define CMD_SUSFS_ADD_SUS_MEMFD 0x60030

#define SUSFS_MAX_LEN_PATHNAME 256
#define SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE 8192
#define SUSFS_ENABLED_FEATURES_SIZE 8192
#define SUSFS_MAX_VERSION_BUFSIZE 16
#define SUSFS_MAX_VARIANT_BUFSIZE 16

#define TRY_UMOUNT_DEFAULT 0
#define TRY_UMOUNT_DETACH 1

#define DEFAULT_KSU_MNT_ID 2000000000
#define DEFAULT_KSU_MNT_GROUP_ID 200000
#define DEFAULT_KSU_MNT_MINOR_DEV (1 << 12)

#define DEFAULT_SUS_MNT_ID 100000
#define DEFAULT_SUS_MNT_ID_FOR_KSU_PROC_UNSHARE 1000000
#define DEFAULT_SUS_MNT_GROUP_ID 1000

#define MAGIC_MOUNT_WORKDIR "/debug_ramdisk/workdir"
#define DATA_ADB_UMOUNT_FOR_ZYGOTE_SYSTEM_PROCESS "/data/adb/susfs_umount_for_zygote_system_process"
#define DATA_ADB_NO_AUTO_ADD_SUS_BIND_MOUNT "/data/adb/susfs_no_auto_add_sus_bind_mount"
#define DATA_ADB_NO_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT "/data/adb/susfs_no_auto_add_sus_ksu_default_mount"
#define DATA_ADB_NO_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT "/data/adb/susfs_no_auto_add_try_umount_for_bind_mount"

#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif

#define VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT 0x80000000

#define TIF_NON_ROOT_USER_APP_PROC 33
#define TIF_PROC_SU_NOT_ALLOWED 34
#define TIF_PROC_UMOUNTED 33
#define TIF_PROC_NO_SU 34
#define TIF_PROC_UMOUNTED_FOR_ZYGOTE_NEXT 35

#define AS_FLAGS_SUS_PATH 24
#define AS_FLAGS_SUS_MOUNT 25
#define AS_FLAGS_SUS_KSTAT 26
#define AS_FLAGS_OPEN_REDIRECT 27
#define AS_FLAGS_ANDROID_DATA_ROOT_DIR 28
#define AS_FLAGS_SDCARD_ROOT_DIR 29
#define AS_FLAGS_SUS_MAP 30

#define BIT_SUS_PATH BIT(24)
#define BIT_SUS_MOUNT BIT(25)
#define BIT_SUS_KSTAT BIT(26)
#define BIT_OPEN_REDIRECT BIT(27)
#define BIT_ANDROID_DATA_ROOT_DIR BIT(28)
#define BIT_ANDROID_SDCARD_ROOT_DIR BIT(29)
#define BIT_SUS_MAP BIT(30)

#ifndef INODE_STATE_SUS_PATH
#define INODE_STATE_SUS_PATH (1 << 26)
#endif
#ifndef INODE_STATE_SUS_MOUNT
#define INODE_STATE_SUS_MOUNT (1 << 27)
#endif
#ifndef INODE_STATE_SUS_KSTAT
#define INODE_STATE_SUS_KSTAT (1 << 28)
#endif
#ifndef INODE_STATE_OPEN_REDIRECT
#define INODE_STATE_OPEN_REDIRECT (1 << 29)
#endif

#define ND_STATE_LOOKUP_LAST 32
#define ND_STATE_OPEN_LAST 64
#define ND_STATE_LAST_SDCARD_SUS_PATH 128
#define ND_FLAGS_LOOKUP_LAST 0x2000000

static inline bool susfs_is_untrusted_app_process(void) {
	/* In Android AOSP, unprivileged third-party apps always have AID_APP_START = 10000 (per user: uid % 100000 >= 10000) */
	uid_t app_id = current_uid().val % 100000;
	if (app_id < 10000)
		return false;
	return true;
}

static inline bool susfs_is_current_non_root_user_app_proc(void) {
	return test_ti_thread_flag(&current->thread_info, TIF_NON_ROOT_USER_APP_PROC);
}

static inline void susfs_set_current_non_root_user_app_proc(void) {
	set_ti_thread_flag(&current->thread_info, TIF_NON_ROOT_USER_APP_PROC);
}

static inline bool susfs_is_current_proc_su_not_allowed(void) {
	return test_ti_thread_flag(&current->thread_info, TIF_PROC_SU_NOT_ALLOWED);
}

static inline void susfs_set_current_proc_su_not_allowed(void) {
	set_ti_thread_flag(&current->thread_info, TIF_PROC_SU_NOT_ALLOWED);
}

static inline bool susfs_is_current_proc_umounted(void) {
	return test_ti_thread_flag(&current->thread_info, TIF_PROC_UMOUNTED);
}

static inline void susfs_set_current_proc_umounted(void) {
	set_ti_thread_flag(&current->thread_info, TIF_PROC_UMOUNTED);
}

static inline void susfs_clear_current_proc_umounted(void) {
	clear_ti_thread_flag(&current->thread_info, TIF_PROC_UMOUNTED);
}

static inline bool susfs_is_current_proc_umounted_app(void) {
	return test_ti_thread_flag(&current->thread_info, TIF_PROC_UMOUNTED) && (current_uid().val % 100000) >= 10000;
}

static inline const char *susfs_strcasestr(const char *haystack, const char *needle) {
	size_t hlen, nlen;
	if (!haystack || !needle)
		return NULL;
	nlen = strlen(needle);
	if (!nlen)
		return haystack;
	hlen = strlen(haystack);
	while (hlen >= nlen) {
		if (strncasecmp(haystack, needle, nlen) == 0)
			return haystack;
		haystack++;
		hlen--;
	}
	return NULL;
}

static inline bool susfs_is_auto_stealth_dentry_name(const char *name) {
	if (!name || !susfs_is_untrusted_app_process())
		return false;

	/* 1. Root, Recovery & Module exact artifact names */
	if (!strcmp(name, "50-lineage.sh") ||
	    !strcmp(name, "addon.d") ||
	    !strcmp(name, "nikgapps_logs") || !strcmp(name, "NoActive") ||
	    !strcmp(name, "lspd") || !strcmp(name, "zygisk_vector") ||
	    !strcmp(name, "vector.dex") || !strcmp(name, "liboat_hook64.so") ||
	    !strcmp(name, "liboat_hook32.so"))
		return true;

	/* 2. SUI / HMA / Hook module residue signatures */
	if (susfs_strcasestr(name, "hide_my_applist") ||
	    susfs_strcasestr(name, "sui_shell") ||
	    susfs_strcasestr(name, "simpleHook") ||
	    susfs_strcasestr(name, "byyang") ||
	    susfs_strcasestr(name, "vector_"))
		return true;

	/* 3. Target custom ROM init & build logs */
	if (susfs_strcasestr(name, "Logs-alioth-NikGapps") ||
	    susfs_strcasestr(name, "Logs-NikGapps") ||
	    !strncmp(name, "init.lineage", 12))
		return true;

	return false;
}

static inline bool susfs_is_auto_stealth_path(const char *p);

static inline bool susfs_is_cross_app_android_data_probe(const char *p) {
	/* Avoid comm truncation false-positives; defer to standard Android AppOps/SuSFS */
	return false;
}

static inline bool susfs_is_cross_app_android_data_dentry(const char *name) {
	return false;
}

static inline bool susfs_is_auto_stealth_path(const char *p) {
	if (!p || !susfs_is_untrusted_app_process())
		return false;

	/* Fast Reject for Non-Slash or Empty string */
	if (p[0] != '/')
		return false;

	/* Fast Branch 1: /system, /system_ext, /product, /vendor */
	if (p[1] == 's' || p[1] == 'p' || p[1] == 'v') {
		/* Fast Bypass for core frameworks, resource apks and overlays */
		if (strstr(p, "/framework") || strstr(p, "/overlay") ||
		    strstr(p, "-res.apk"))
			return false;

		if (strstr(p, "/system/addon.d"))
			return true;
	}

	/* Fast Branch 2: /data paths */
	if (p[1] == 'd' && p[2] == 'a' && p[3] == 't' && p[4] == 'a' && p[5] == '/') {
		char sub = p[6];
		if (sub == 'a' && !strncmp(p + 6, "adb", 3))
			return true;
		if (sub == 'l' && strstr(p, "/data/local/tmp/"))
			return true;
		if (sub == 'm' && (strstr(p, "/data/misc/hide_my_applist") ||
				   strstr(p, "/data/misc/zygisk") ||
				   strstr(p, "/data/misc/magisk")))
			return true;
		if (sub == 's' && strstr(p, "/data/system/NoActive"))
			return true;
	}

	/* Fast Branch 3: /dev properties */
	if (p[1] == 'd' && p[2] == 'e' && p[3] == 'v' && p[4] == '/') {
		if (strstr(p, "/dev/__properties__/u:object_r:qemu_hw_prop:s0"))
			return true;
	}

	/* Fast Branch 4: /etc init configs */
	if (p[1] == 'e' && p[2] == 't' && p[3] == 'c' && p[4] == '/') {
		if (strstr(p, "/etc/init/init.lineage"))
			return true;
	}

	/* Fast Branch 5: custom ROM / logs */
	if (strstr(p, "/nikgapps_logs") || strstr(p, "50-lineage.sh"))
		return true;

	return false;
}

#endif // #ifndef KSU_SUSFS_DEF_H
