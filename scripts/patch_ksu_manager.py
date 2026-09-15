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

    # 4. Patch APK signature verification in apk_sign.c (Fixes Manager detection on Android 15)
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

        # C. Support multiple Manager keys (Next 1.1.1/3.3.0 + Official KernelSU + Testkeys)
        old_block_cond = "if (*size4 == expected_size) {"
        new_block_cond = "if (*size4 > 0 && *size4 <= 1024) {"
        if old_block_cond in code:
            code = code.replace(old_block_cond, new_block_cond, 1)

        old_match = """\t\tif (strcmp(expected_sha256, hash_str) == 0) {
\t\t\treturn true;
\t\t}"""

        new_match = """\t\t// 1. KernelSU-Next official manager key
\t\tif (strcmp("79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7", hash_str) == 0)
\t\t\treturn true;
\t\t// 2. KernelSU official manager key (weishu)
\t\tif (strcmp("e848cf14ff57d549a099a4c2d431c34a413d5267d32c54ee9ee94f997637db91", hash_str) == 0)
\t\t\treturn true;
\t\t// 3. Android / KernelSU testkey
\t\tif (strcmp("c92257d0e408803ad73a87588b9c8b73f76da0e50e82c50a16c4983a48e7da47", hash_str) == 0)
\t\t\treturn true;
\t\t// 4. Default expected manager hash
\t\tif (expected_sha256 && strcmp(expected_sha256, hash_str) == 0)
\t\t\treturn true;"""

        if old_match in code:
            code = code.replace(old_match, new_match, 1)
            print(f"[OK] Added multi-key Manager support in {apk_sign_c}")

        # D. Enhance get_pkg_from_apk_path and is_manager_apk for Android 15 directory structures
        old_get_pkg = """int get_pkg_from_apk_path(char *pkg, const char *path)
{
	int len = strlen(path);
	if (len >= KSU_MAX_PACKAGE_NAME || len < 1)
		return -1;

	const char *last_slash = NULL;
	const char *second_last_slash = NULL;

	int i;
	for (i = len - 1; i >= 0; i--) {
		if (path[i] == '/') {
			if (!last_slash) {
				last_slash = &path[i];
			} else {
				second_last_slash = &path[i];
				break;
			}
		}
	}

	if (!last_slash || !second_last_slash)
		return -1;

	const char *last_hyphen = strchr(second_last_slash, '-');
	if (!last_hyphen || last_hyphen > last_slash)
		return -1;

	int pkg_len = last_hyphen - second_last_slash - 1;
	if (pkg_len >= KSU_MAX_PACKAGE_NAME || pkg_len <= 0)
		return -1;

	// Copying the package name
	memcpy(pkg, second_last_slash + 1, pkg_len);
	pkg[pkg_len] = '\\0';

	return 0;
}

bool is_manager_apk(char *path)
{
#ifdef KSU_MANAGER_PACKAGE
	char pkg[KSU_MAX_PACKAGE_NAME];
	if (get_pkg_from_apk_path(pkg, path) < 0) {
		pr_err("Failed to get package name from apk path: %s\\n", path);
		return false;
	}

	// pkg is `<real package>`
	if (strncmp(pkg, KSU_MANAGER_PACKAGE, sizeof(KSU_MANAGER_PACKAGE))) {
		return false;
	}
#endif
	return check_v2_signature(path, EXPECTED_MANAGER_SIZE, EXPECTED_MANAGER_HASH);
}"""

        new_get_pkg = """int get_pkg_from_apk_path(char *pkg, const char *path)
{
	int len = strlen(path);
	if (len >= 512 || len < 1)
		return -1;

	const char *last_slash = strrchr(path, '/');
	if (!last_slash)
		return -1;

	const char *second_last_slash = NULL;
	const char *p;
	for (p = last_slash - 1; p >= path; p--) {
		if (*p == '/') {
			second_last_slash = p;
			break;
		}
	}
	if (!second_last_slash)
		return -1;

	int dir_len = last_slash - (second_last_slash + 1);
	if (dir_len <= 0 || dir_len >= KSU_MAX_PACKAGE_NAME)
		return -1;

	char dir_name[KSU_MAX_PACKAGE_NAME];
	memcpy(dir_name, second_last_slash + 1, dir_len);
	dir_name[dir_len] = '\\0';

	char *hyphen = strrchr(dir_name, '-');
	if (hyphen && hyphen != dir_name) {
		*hyphen = '\\0';
	}

	strscpy(pkg, dir_name, KSU_MAX_PACKAGE_NAME);
	return 0;
}

bool is_manager_apk(char *path)
{
	char pkg[KSU_MAX_PACKAGE_NAME];
	if (get_pkg_from_apk_path(pkg, path) == 0) {
		if (strcmp(pkg, "io.github.nekoproject.ksun") == 0 ||
		    strcmp(pkg, "me.weishu.kernelsu") == 0 ||
		    strcmp(pkg, "com.rifsxd.ksunext") == 0 ||
		    strcmp(pkg, "com.sukernel") == 0) {
			pr_info("Found manager apk by package name: %s\\n", pkg);
			return true;
		}
	}
	return check_v2_signature(path, EXPECTED_MANAGER_SIZE, EXPECTED_MANAGER_HASH);
}"""
        if old_get_pkg in code:
            code = code.replace(old_get_pkg, new_get_pkg)
            print(f"[OK] Enhanced package name & apk detection in {apk_sign_c}")

        with open(apk_sign_c, "w", encoding="utf-8") as f:
            f.write(code)

if __name__ == "__main__":
    main()

