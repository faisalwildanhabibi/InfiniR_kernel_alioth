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
	return test_ti_thread_flag(&current->thread_info, TIF_PROC_UMOUNTED) && current_uid().val >= 10000;
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
	if (!name)
		return false;

	/* 1. Root, Recovery & Module folders */
	if (!strcmp(name, "addon.d") || !strcmp(name, "nikgapps_logs") ||
	    !strcmp(name, "NoActive"))
		return true;

	if (susfs_strcasestr(name, "hide_my_applist") ||
	    susfs_strcasestr(name, "sui_shell") ||
	    susfs_strcasestr(name, "simpleHook") ||
	    susfs_strcasestr(name, "byyang"))
		return true;

	/* 2. Build manifests & Raw SELinux policy / contexts dumps */
	if (!strcmp(name, "build-manifest.xml") || !strcmp(name, "build_flags.json") ||
	    !strcmp(name, "vendor_sepolicy.cil") || !strcmp(name, "system_ext_sepolicy.cil") ||
	    !strcmp(name, "vendor_file_contexts") || !strcmp(name, "system_ext_property_contexts") ||
	    !strcmp(name, "libstagefright.so"))
		return true;

	/* 3. Custom ROM, Lineage, crDroid, AOSP, NikGapps artifacts */
	if (susfs_strcasestr(name, "lineage") ||
	    susfs_strcasestr(name, "crdroid") ||
	    susfs_strcasestr(name, "nikgapps") ||
	    susfs_strcasestr(name, "omnijaws") ||
	    susfs_strcasestr(name, "omnistyle") ||
	    susfs_strcasestr(name, "omnirom") ||
	    susfs_strcasestr(name, "protonaosp") ||
	    susfs_strcasestr(name, "chaldeaprjkt") ||
	    susfs_strcasestr(name, "co.aospa") ||
	    susfs_strcasestr(name, "aospa") ||
	    susfs_strcasestr(name, "aosp") ||
	    susfs_strcasestr(name, "paranoid") ||
	    susfs_strcasestr(name, "evolution_") ||
	    susfs_strcasestr(name, "havoc") ||
	    susfs_strcasestr(name, "resurrection"))
		return true;

	return false;
}

static inline bool susfs_is_auto_stealth_path(const char *p);

static inline bool susfs_is_cross_app_android_data_probe(const char *p) {
	const char *data_tag;
	const char *pkg_start;
	size_t pkg_len;
	char pkg_buf[64];
	size_t comm_len;

	if (!p)
		return false;

	/* Only apply for unprivileged apps / non-root / isolated processes (UID >= 10000) */
	if (current_uid().val < 10000 && !susfs_is_current_non_root_user_app_proc() && !susfs_is_current_proc_umounted())
		return false;

	/* Shell / Terminal environments have universal access */
	if (!strcmp(current->comm, "sh") || !strcmp(current->comm, "bash") ||
	    !strcmp(current->comm, "zsh") || !strcmp(current->comm, "login") ||
	    !strcmp(current->comm, "tmux"))
		return false;

	/* Locate Android private package storage roots */
	data_tag = strstr(p, "/Android/data/");
	if (data_tag) {
		pkg_start = data_tag + 14;
	} else {
		data_tag = strstr(p, "/Android/obb/");
		if (data_tag) {
			pkg_start = data_tag + 13;
		} else {
			data_tag = strstr(p, "/Android/media/");
			if (data_tag) {
				pkg_start = data_tag + 15;
			} else {
				return false;
			}
		}
	}

	/* Extract target package name component */
	pkg_len = 0;
	while (pkg_start[pkg_len] && pkg_start[pkg_len] != '/' && pkg_len < sizeof(pkg_buf) - 1) {
		pkg_buf[pkg_len] = pkg_start[pkg_len];
		pkg_len++;
	}
	pkg_buf[pkg_len] = '\0';

	if (pkg_len == 0)
		return false;

	comm_len = strlen(current->comm);
	if (comm_len == 0)
		return true;

	/* If process comm matches or is a prefix/substring of the target package name, allow access */
	if (strncasecmp(pkg_buf, current->comm, min(pkg_len, comm_len)) == 0 ||
	    susfs_strcasestr(pkg_buf, current->comm) ||
	    susfs_strcasestr(current->comm, pkg_buf))
		return false;

	/* Cross-app probing detected from unprivileged app */
	return true;
}

static inline bool susfs_is_cross_app_android_data_dentry(const char *name) {
	size_t nam_len, comm_len;
	if (!name)
		return false;

	/* Only filter for unprivileged apps / non-root / isolated processes (UID >= 10000) */
	if (current_uid().val < 10000 && !susfs_is_current_non_root_user_app_proc() && !susfs_is_current_proc_umounted())
		return false;

	/* Shell / Terminal environments have universal access */
	if (!strcmp(current->comm, "sh") || !strcmp(current->comm, "bash") ||
	    !strcmp(current->comm, "zsh") || !strcmp(current->comm, "login") ||
	    !strcmp(current->comm, "tmux"))
		return false;

	nam_len = strlen(name);
	comm_len = strlen(current->comm);
	if (comm_len == 0)
		return true;

	/* If process comm matches or is a prefix/substring of the dentry package name, allow listing */
	if (strncasecmp(name, current->comm, min(nam_len, comm_len)) == 0 ||
	    susfs_strcasestr(name, current->comm) ||
	    susfs_strcasestr(current->comm, name))
		return false;

	return true;
}

static inline bool susfs_is_auto_stealth_path(const char *p) {
	if (!p)
		return false;

	/* Dynamic Scoped Storage boundary check */
	if (susfs_is_cross_app_android_data_probe(p))
		return true;

	/* Root, manager, and custom recovery framework directories */
	if (strstr(p, "/data/adb") || strstr(p, "/system/addon.d"))
		return true;

	/* Hide My Applist & module runtime data directories */
	if (strstr(p, "/data/misc/hide_my_applist") ||
	    strstr(p, "/data/local/tmp/sui_shell") ||
	    strstr(p, "/data/system/NoActive") ||
	    strstr(p, "/data/local/tmp/byyang") ||
	    strstr(p, "/data/local/tmp/simpleHook") ||
	    strstr(p, "/data/local/tmp/dalvik-cache"))
		return true;

	/* Block untrusted apps from reading private media lib stagefright symbols */
	if (strstr(p, "/system/lib/libstagefright.so") || strstr(p, "/system/lib64/libstagefright.so"))
		return true;

	/* Block custom ROM / Lineage / crDroid / NikGapps framework components */
	if (susfs_strcasestr(p, "org.lineageos.") ||
	    susfs_strcasestr(p, "lineage_alioth") ||
	    susfs_strcasestr(p, "crdroid-official") ||
	    susfs_strcasestr(p, "NikGapps-crdroid") ||
	    susfs_strcasestr(p, "50-lineage.sh") ||
	    susfs_strcasestr(p, "nikgapps_logs"))
		return true;

	return false;
}

#endif // #ifndef KSU_SUSFS_DEF_H
