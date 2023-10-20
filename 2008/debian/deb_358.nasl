# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53647");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0018", "CVE-2003-0461", "CVE-2003-0462", "CVE-2003-0476", "CVE-2003-0501", "CVE-2003-0550", "CVE-2003-0551", "CVE-2003-0552", "CVE-2003-0619");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Debian Security Advisory DSA 358-1 (linux-kernel-i386, linux-kernel-alpha)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20358-1");
  script_tag(name:"insight", value:"A number of vulnerabilities have been discovered in the Linux kernel.

For a more detailed description of the problems addressed,
please visit the referenced security advisory.

This advisory covers only the i386 and alpha architectures.  Other
architectures will be covered by separate advisories.

For the stable distribution (woody) on the i386 architecture, these
problems have been fixed in kernel-source-2.4.18 version 2.4.18-11,
kernel-image-2.4.18-1-i386 version 2.4.18-9, and
kernel-image-2.4.18-i386bf version 2.4.18-5woody2.

For the stable distribution (woody) on the alpha architecture, these
problems have been fixed in kernel-source-2.4.18 version 2.4.18-11 and
kernel-image-2.4.18-1-alpha version 2.4.18-8.

For the unstable distribution (sid) these problems are fixed in
kernel-source-2.4.20 version 2.4.20-9.

We recommend that you update your kernel packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to linux-kernel-i386, linux-kernel-alpha
announced via advisory DSA 358-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-386", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-586tsc", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-686", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-686-smp", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-k6", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-k7", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-386", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-586tsc", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-686", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-686-smp", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-k6", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-k7", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-386", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-586tsc", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-686", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-686-smp", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-k6", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-k7", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-bf2.4", ver:"2.4.18-5woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-bf2.4", ver:"2.4.18-5woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-generic", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-smp", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-generic", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-smp", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-doc-2.4.18", ver:"2.4.18-11", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-source-2.4.18", ver:"2.4.18-11", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
