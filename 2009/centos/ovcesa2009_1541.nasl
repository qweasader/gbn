#CESA-2009:1541 66218 2
# Description: Auto-generated from advisory CESA-2009:1541 (kernel)
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
  script_oid("1.3.6.1.4.1.25623.1.0.66218");
  script_version("2022-01-21T06:45:22+0000");
  script_tag(name:"last_modification", value:"2022-01-21 06:45:22 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
  script_cve_id("CVE-2009-3547");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 15:44:00 +0000 (Wed, 12 Aug 2020)");
  script_name("CentOS Security Advisory CESA-2009:1541 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"insight", value:"For details on the issues addressed in this update,
please visit the referenced security advisories.");
  script_tag(name:"solution", value:"Update the appropriate packages on your system.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=CESA-2009:1541");
  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=RHSA-2009:1541");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2009-1541.html");
  script_tag(name:"summary", value:"The remote host is missing updates to kernel announced in
advisory CESA-2009:1541.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~89.0.16.EL", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~89.0.16.EL", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~89.0.16.EL", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~89.0.16.EL", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~89.0.16.EL", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~89.0.16.EL", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~89.0.16.EL", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~89.0.16.EL", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~89.0.16.EL", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-largesmp", rpm:"kernel-largesmp~2.6.9~89.0.16.EL", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-largesmp-devel", rpm:"kernel-largesmp-devel~2.6.9~89.0.16.EL", rls:"CentOS4")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
