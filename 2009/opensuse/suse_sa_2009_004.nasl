# OpenVAS Vulnerability Test
#
# Auto-generated from advisory SUSE-SA:2009:004 (kernel)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63273");
  script_version("2022-01-20T14:18:20+0000");
  script_tag(name:"last_modification", value:"2022-01-20 14:18:20 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-01-26 18:18:20 +0100 (Mon, 26 Jan 2009)");
  script_cve_id("CVE-2008-4933", "CVE-2008-5025", "CVE-2008-5029", "CVE-2008-5079", "CVE-2008-5134", "CVE-2008-5182");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Security Advisory SUSE-SA:2009:004 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE10\.3");
  script_tag(name:"insight", value:"The openSUSE 10.3 kernel was updated to fix various security problems
and bugs. The following security bugs were fixed:

CVE-2008-5079: net/atm/svc.c in the ATM subsystem allowed local users
to cause a denial of service (kernel infinite loop) by making two calls
to svc_listen for the same socket, and then reading a /proc/net/atm/*vc
file, related to corruption of the vcc table.

CVE-2008-5029: The __scm_destroy function in net/core/scm.c makes
indirect recursive calls to itself through calls to the fput function,
which allows local users to cause a denial of service (panic) via
vectors related to sending an SCM_RIGHTS message through a UNIX domain
socket and closing file descriptors.

CVE-2008-5134: Buffer overflow in the lbs_process_bss function
in drivers/net/wireless/libertas/scan.c in the libertas subsystem
allowed remote attackers to have an unknown impact via an invalid
beacon/probe response.

CVE-2008-4933: Buffer overflow in the hfsplus_find_cat function in
fs/hfsplus/catalog.c allowed attackers to cause a denial of service
(memory corruption or system crash) via an hfsplus filesystem
image with an invalid catalog namelength field, related to the
hfsplus_cat_build_key_uni function.

CVE-2008-5025: Stack-based buffer overflow in the hfs_cat_find_brec
function in fs/hfs/catalog.c allowed attackers to cause a denial of
service (memory corruption or system crash) via an hfs filesystem
image with an invalid catalog namelength field, a related issue to
CVE-2008-4933.

CVE-2008-5182: The inotify functionality might allow local users to
gain privileges via unknown vectors related to race conditions in
inotify watch removal and umount.");
  script_tag(name:"solution", value:"Update your system with the packages as indicated in
  the referenced security advisory.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:004");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory SUSE-SA:2009:004.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.22.19~0.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.22.19~0.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.22.19~0.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.22.19~0.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.22.19~0.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.22.19~0.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.22.19~0.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.22.19~0.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~2.6.22.19~0.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
