/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _XT_TCPMSS_MATCH_H
#define _XT_TCPMSS_MATCH_H

#include <linux/types.h>

struct xt_tcpmss_match_info {
	__u16 min_mss, max_mss;
	__u8 invert;
};

#endif /* _XT_TCPMSS_MATCH_H */
