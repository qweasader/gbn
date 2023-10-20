# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53407");
  script_version("2023-06-29T08:15:14+0000");
  script_tag(name:"last_modification", value:"2023-06-29 08:15:14 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-0391");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 146-1 (dietlibc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20146-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5356");
  script_tag(name:"insight", value:"An integer overflow bug has been discovered in the RPC library used by
dietlibc, a libc optimized for small size, which is derived from the
SunRPC library.  This bug could be exploited to gain unauthorized root
access to software linking to this code.  The packages below also fix
integer overflows in the calloc, fread and fwrite code.  They are also
more strict regarding hostile DNS packets that could lead to a
vulnerability otherwise.

These problems have been fixed in version 0.12-2.2 for the current
stable distribution (woody) and in version 0.20-0cvs20020806 for the
unstable distribution (sid).  Debian 2.2 (potato) is not affected
since it doesn't contain dietlibc packages.");

  script_tag(name:"solution", value:"We recommend that you upgrade your dietlibc packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to dietlibc announced via advisory DSA 146-1.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-146)' (OID: 1.3.6.1.4.1.25623.1.0.53408).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);