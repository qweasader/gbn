#CESA-2009:0473 63970 2
# Description: Auto-generated from advisory CESA-2009:0473 (kernel)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2009 E-Soft Inc.
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63970");
  script_version("2022-01-21T06:45:22+0000");
  script_tag(name:"last_modification", value:"2022-01-21 06:45:22 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-05-11 20:24:31 +0200 (Mon, 11 May 2009)");
  script_cve_id("CVE-2008-4307", "CVE-2009-0787", "CVE-2009-0834", "CVE-2009-1336", "CVE-2009-1337");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_name("CentOS Security Advisory CESA-2009:0473 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"insight", value:"For details on the issues addressed in this update,
please visit the referenced security advisories.");
  script_tag(name:"solution", value:"Update the appropriate packages on your system.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=CESA-2009:0473");
  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=RHSA-2009:0473");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2009-0473.html");
  script_tag(name:"summary", value:"The remote host is missing updates to kernel announced in
advisory CESA-2009:0473.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}