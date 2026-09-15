import os
import sys

def patch_file(path, old_str, new_str):
    if not os.path.exists(path):
        print(f"[WARN] File not found: {path}")
        return False
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    if old_str in content:
        content = content.replace(old_str, new_str)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[OK] Patched {path}")
        return True
    elif new_str in content:
        print(f"[OK] Already patched: {path}")
        return True
    else:
        print(f"[WARN] Target string not found in {path}")
        return False

def main():
    ksu_dir = sys.argv[1] if len(sys.argv) > 1 else "KernelSU-Next"
    
    # 1. Patch SELinux uninitialized SID checks (fixes early boot init freeze)
    selinux_c = os.path.join(ksu_dir, "kernel", "selinux", "selinux.c")
    patch_file(selinux_c, 
               "return unlikely(current_sid() == susfs_zygote_sid);",
               "return unlikely(susfs_zygote_sid && current_sid() == susfs_zygote_sid);")
    patch_file(selinux_c,
               "return unlikely(current_sid() == susfs_ksu_sid);",
               "return unlikely(susfs_ksu_sid && current_sid() == susfs_ksu_sid);")
    patch_file(selinux_c,
               "return unlikely(current_sid() == susfs_init_sid);",
               "return unlikely(susfs_init_sid && current_sid() == susfs_init_sid);")

    # 2. Patch manager_identity.h to treat root (UID 0) as manager as well
    mgr_id_h = os.path.join(ksu_dir, "kernel", "manager", "manager_identity.h")
    if os.path.exists(mgr_id_h):
        old_is_mgr = """static inline bool is_manager()
{
	return unlikely(ksu_manager_appid == current_uid().val % KSU_PER_USER_RANGE);
}"""
        new_is_mgr = """static inline bool is_manager()
{
	if (current_uid().val == 0)
		return true;
	if (ksu_manager_appid != KSU_INVALID_APPID &&
	    ksu_manager_appid == current_uid().val % KSU_PER_USER_RANGE)
		return true;
	return false;
}"""
        patch_file(mgr_id_h, old_is_mgr, new_is_mgr)

    # 3. Patch supercall.c (Auto-crowning manager on install_fd & SuSFS info query permissions)
    supercall_c = os.path.join(ksu_dir, "kernel", "supercall", "supercall.c")
    if os.path.exists(supercall_c):
        with open(supercall_c, "r", encoding="utf-8", errors="ignore") as f:
            sc_code = f.read()

        # A. Allow SuSFS info queries for manager and read-only commands
        old_susfs_perm = "if (magic2 == SUSFS_MAGIC && current_uid().val == 0) {"
        new_susfs_perm = "if (magic2 == SUSFS_MAGIC && (current_uid().val == 0 || is_manager() || cmd == CMD_SUSFS_SHOW_VERSION || cmd == CMD_SUSFS_SHOW_VARIANT || cmd == CMD_SUSFS_SHOW_ENABLED_FEATURES)) {"
        if old_susfs_perm in sc_code:
            sc_code = sc_code.replace(old_susfs_perm, new_susfs_perm)
            print(f"[OK] Patched SuSFS query permissions in {supercall_c}")

        # B. Auto-crown manager on install_fd if not yet crowned
        old_install_fd = """\t\tif (copy_to_user((void __user *)*arg, &fd, sizeof(fd))) {
\t\t\tpr_err("install ksu fd reply err\\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
\t\tclose_fd(fd);
#else
\t\t__close_fd(current->files, fd);
#endif
\t\t}
\t\treturn 0;"""

        new_install_fd = """\t\tif (copy_to_user((void __user *)*arg, &fd, sizeof(fd))) {
\t\t\tpr_err("install ksu fd reply err\\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
\t\tclose_fd(fd);
#else
\t\t__close_fd(current->files, fd);
#endif
\t\t} else {
\t\t\tif (!ksu_is_manager_appid_valid()) {
\t\t\t\tuid_t appid = current_uid().val % KSU_PER_USER_RANGE;
\t\t\t\tif (appid >= 10000) {
\t\t\t\t\tpr_info("ksu: auto-crowning manager appid %d from install_fd\\n", appid);
\t\t\t\t\tksu_set_manager_appid(appid);
\t\t\t\t}
\t\t\t}
\t\t}
\t\treturn 0;"""
        if old_install_fd in sc_code:
            sc_code = sc_code.replace(old_install_fd, new_install_fd)
            print(f"[OK] Patched install_fd auto-crowning in {supercall_c}")

        with open(supercall_c, "w", encoding="utf-8") as f:
            f.write(sc_code)

    # 4. Patch APK signature verification in apk_sign.c (Fixes Manager detection on Android 15 while keeping upstream hash)
    apk_sign_c = os.path.join(ksu_dir, "kernel", "manager", "apk_sign.c")
    if os.path.exists(apk_sign_c):
        with open(apk_sign_c, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()

        # A. Remove v3 signature rejection so Android 15 dual-signed APKs pass
        old_v3_check = """\tif (v3_signing_exist || v3_1_signing_exist) {
#ifdef CONFIG_KSU_DEBUG
\t\tpr_err("Unexpected v3 signature scheme found!\\n");
#endif
\t\treturn false;
\t}"""
        if old_v3_check in code:
            code = code.replace(old_v3_check, "/* v3 signature scheme allowed on Android 11+ */")
            print(f"[OK] Removed strict v3 signature rejection in {apk_sign_c}")

        # B. Allow v1 signature alongside v2
        old_v1_check = """\tif (v2_signing_valid) {
\t\tint has_v1_signing = has_v1_signature_file(fp);
\t\tif (has_v1_signing) {
\t\t\tpr_err("Unexpected v1 signature scheme found!\\n");
\t\t\tfilp_close(fp, 0);
\t\t\treturn false;
\t\t}
\t}"""
        new_v1_check = """\tif (v2_signing_valid) {
\t\t// Allow v1 signature alongside v2 for standard production APKs
\t\t(void)has_v1_signature_file;
\t}"""
        if old_v1_check in code:
            code = code.replace(old_v1_check, new_v1_check)
            print(f"[OK] Removed strict v1 signature rejection in {apk_sign_c}")

        # C. Allow flexible certificate block length for upstream expected_sha256
        old_block_cond = "if (*size4 == expected_size) {"
        new_block_cond = "if (*size4 > 0 && *size4 <= 1024) {"
        if old_block_cond in code:
            code = code.replace(old_block_cond, new_block_cond, 1)
            print(f"[OK] Enabled flexible cert block length in {apk_sign_c}")

        # D. Support official KernelSU-Next, official KernelSU, and testkey manager signatures
        old_match = """\t\tif (strcmp(expected_sha256, hash_str) == 0) {
\t\t\treturn true;
\t\t}"""

        new_match = """\t\tif (strcmp("79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7", hash_str) == 0 ||
\t\t    strcmp("e848cf14ff57d549a099a4c2d431c34a413d5267d32c54ee9ee94f997637db91", hash_str) == 0 ||
\t\t    strcmp("c92257d0e408803ad73a87588b9c8b73f76da0e50e82c50a16c4983a48e7da47", hash_str) == 0 ||
\t\t    (expected_sha256 && strcmp(expected_sha256, hash_str) == 0)) {
\t\t\treturn true;
\t\t}"""
        if old_match in code:
            code = code.replace(old_match, new_match, 1)
            print(f"[OK] Added multi-signature manager support in {apk_sign_c}")

        with open(apk_sign_c, "w", encoding="utf-8") as f:
            f.write(code)

        # E. Path length safe for get_pkg_from_apk_path
        patch_file(apk_sign_c,
                   "if (len >= KSU_MAX_PACKAGE_NAME || len < 1)",
                   "if (len >= 512 || len < 1)")

    # 5. Patch Kbuild to dynamically resolve KSU_GIT_VERSION and KSU_VERSION_TAG from environment or git
    kbuild_file = os.path.join(ksu_dir, "kernel", "Kbuild")
    if os.path.exists(kbuild_file):
        with open(kbuild_file, "r", encoding="utf-8", errors="ignore") as f:
            kb_code = f.read()

        old_kbuild_calc = '''# Calculate version if git version is available
ifdef KSU_GIT_VERSION_VALID
# ksu_version: major * 30000 + git version for historical reasons
$(eval KSU_VERSION=$(shell expr 30000 + $(KSU_GIT_VERSION) + 200))
$(info -- KernelSU-Next version: $(KSU_VERSION))
ccflags-y += -DKSU_VERSION=$(KSU_VERSION)
else
# If there is no .git directory, use default version
$(warning "KSU_GIT_VERSION not defined! It is better to make KernelSU-Next a git repository!")
KSU_VERSION_FALLBACK := 1
$(info -- KernelSU-Next version fallback: $(KSU_VERSION_FALLBACK))
ccflags-y += -DKSU_VERSION=$(KSU_VERSION_FALLBACK)
endif

ifdef KSU_GIT_VERSION_VALID
$(eval KSU_VERSION_TAG=$(KSU_GIT_TAG))
$(info -- KernelSU-Next tag: $(KSU_VERSION_TAG))
ccflags-y += -DKSU_VERSION_TAG=\\"$(KSU_VERSION_TAG)\\"
else
$(warning "KSU_VERSION_TAG not defined! It is better to make KernelSU-Next a git submodule!")
KSU_VERSION_TAG_FALLBACK := v0.0.1
$(info -- KernelSU-Next tag fallback: $(KSU_VERSION_TAG_FALLBACK))
ccflags-y += -DKSU_VERSION_TAG=\\"$(KSU_VERSION_TAG_FALLBACK)\\"
endif'''

        new_kbuild_calc = '''# Dynamically resolve version from environment or git
ifdef KSU_GIT_VERSION
KSU_GIT_VERSION_VALID := 1
KSU_GIT_TAG := $(KSU_VERSION_TAG)
endif

ifdef KSU_GIT_VERSION_VALID
# ksu_version: major * 30000 + git version for historical reasons
$(eval KSU_VERSION=$(shell expr 30000 + $(KSU_GIT_VERSION) + 200))
$(info -- KernelSU-Next version: $(KSU_VERSION))
ccflags-y += -DKSU_VERSION=$(KSU_VERSION)
ifdef KSU_VERSION_TAG
$(info -- KernelSU-Next tag: $(KSU_VERSION_TAG))
ccflags-y += -DKSU_VERSION_TAG=\\"$(KSU_VERSION_TAG)\\"
else
$(eval KSU_VERSION_TAG=$(KSU_GIT_TAG))
$(info -- KernelSU-Next tag: $(KSU_VERSION_TAG))
ccflags-y += -DKSU_VERSION_TAG=\\"$(KSU_VERSION_TAG)\\"
endif
else
# If no git info available, try to query git directly
KSU_DETECTED_VER := $(shell cd $(KSU_KERNEL_DIR) && git rev-list --count HEAD 2>/dev/null)
KSU_DETECTED_TAG := $(shell cd $(KSU_KERNEL_DIR) && git describe --tags --abbrev=0 2>/dev/null)
ifneq ($(KSU_DETECTED_VER),)
$(eval KSU_VERSION=$(shell expr 30000 + $(KSU_DETECTED_VER) + 200))
$(info -- KernelSU-Next version: $(KSU_VERSION))
ccflags-y += -DKSU_VERSION=$(KSU_VERSION)
$(info -- KernelSU-Next tag: $(KSU_DETECTED_TAG))
ccflags-y += -DKSU_VERSION_TAG=\\"$(KSU_DETECTED_TAG)\\"
endif
endif'''

        if old_kbuild_calc in kb_code:
            kb_code = kb_code.replace(old_kbuild_calc, new_kbuild_calc)
            with open(kbuild_file, "w", encoding="utf-8") as f:
                f.write(kb_code)
            print(f"[OK] Patched Kbuild dynamic version and tag calculations in {kbuild_file}")

    # 6. Patch core/init.c to initialize observer for built-in kernel mode
    init_c = os.path.join(ksu_dir, "kernel", "core", "init.c")
    if os.path.exists(init_c):
        with open(init_c, "r", encoding="utf-8", errors="ignore") as f:
            init_code = f.read()
        old_init_tail = """\t\tksu_ksud_init();

\t\tksu_file_wrapper_init();
\t}"""
        new_init_tail = """\t\tksu_ksud_init();

\t\tksu_file_wrapper_init();

\t\tksu_observer_init();
\t}"""
        if old_init_tail in init_code:
            init_code = init_code.replace(old_init_tail, new_init_tail)
            with open(init_c, "w", encoding="utf-8") as f:
                f.write(init_code)
            print(f"[OK] Added ksu_observer_init to built-in init in {init_c}")

    # 7. Patch hook/lsm_hooks.c to allow throne tracking during boot
    lsm_hooks_c = os.path.join(ksu_dir, "kernel", "hook", "lsm_hooks.c")
    if os.path.exists(lsm_hooks_c):
        patch_file(lsm_hooks_c,
                   "if (!ksu_boot_completed) {\n\t\treturn 0;\n\t}",
                   "// allow throne tracking during system server initialization\n\t(void)ksu_boot_completed;")

    # 8. Patch hook/setuid_hook.c to disable seccomp for uncrowned app processes
    setuid_c = os.path.join(ksu_dir, "kernel", "hook", "setuid_hook.c")
    if os.path.exists(setuid_c):
        with open(setuid_c, "r", encoding="utf-8", errors="ignore") as f:
            setuid_code = f.read()

        old_manager_check = """    if (unlikely(is_uid_manager(new_uid))) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        }
#else
		disable_seccomp(current);
#endif"""

        new_manager_check = """    if (unlikely(is_uid_manager(new_uid) || !ksu_is_manager_appid_valid())) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        }
#else
		disable_seccomp(current);
#endif"""
        if old_manager_check in setuid_code:
            setuid_code = setuid_code.replace(old_manager_check, new_manager_check)
            with open(setuid_c, "w", encoding="utf-8") as f:
                f.write(setuid_code)
            print(f"[OK] Patched uncrowned manager seccomp bypass in {setuid_c}")

    # 9. Patch dispatch.c to set KSU_GET_INFO_FLAG_MANAGER for uncrowned manager
    dispatch_c = os.path.join(ksu_dir, "kernel", "supercall", "dispatch.c")
    if os.path.exists(dispatch_c):
        patch_file(dispatch_c,
                   "if (is_manager()) {\n\t\tcmd.flags |= KSU_GET_INFO_FLAG_MANAGER;\n\t}",
                   "if (is_manager() || !ksu_is_manager_appid_valid()) {\n\t\tcmd.flags |= KSU_GET_INFO_FLAG_MANAGER;\n\t}")

if __name__ == "__main__":
    main()

