# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53423");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-0391");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 149-2 (glibc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20149-2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5356");
  script_tag(name:"insight", value:"Wolfram Gloger discovered that the bugfix from DSA 149-1 unintentionally
replaced potential integer overflows in connection with malloc() with
more likely divisions by zero.  This called for an update.  For
completeness the original security advisory said:

An integer overflow bug has been discovered in the RPC library used
by GNU libc, which is derived from the SunRPC library.  This bug
could be exploited to gain unauthorized root access to software
linking to this code.  The packages below also fix integer overflows
in the malloc code.

This is fixed in version 2.2.5-11.2 for the current stable
distribution (woody) by using a patch from the stable glibc-2_2 branch
by Wolfgang and in version 2.1.3-24 for the old stable release
(potato).");

  script_tag(name:"solution", value:"We recommend that you upgrade your libc6 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to glibc
announced via advisory DSA 149-2.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"glibc-doc", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"i18ndata", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-dbg", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-dev", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-pic", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-prof", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss1-compat", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"locales", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nscd", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dbg", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-pic", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-prof", ver:"2.1.3-24", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"glibc-doc", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"locales", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-dbg", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-dev", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-pic", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6.1-prof", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nscd", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dbg", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-pic", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-prof", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-dev-sparc64", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libc6-sparc64", ver:"2.2.5-11.2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
