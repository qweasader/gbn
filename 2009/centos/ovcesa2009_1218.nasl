#CESA-2009:1218 64789 4
# Description: Auto-generated from advisory CESA-2009:1218 (pidgin)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64789");
  script_version("2022-01-21T06:45:22+0000");
  script_tag(name:"last_modification", value:"2022-01-21 06:45:22 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-2694");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Security Advisory CESA-2009:1218 (pidgin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS(5|3)");
  script_tag(name:"insight", value:"For details on the issues addressed in this update,
please visit the referenced security advisories.");
  script_tag(name:"solution", value:"Update the appropriate packages on your system.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=CESA-2009:1218");
  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=RHSA-2009:1218");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2009-1218.html");
  script_tag(name:"summary", value:"The remote host is missing updates to pidgin announced in
advisory CESA-2009:1218.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.5.9~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.5.9~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.5.9~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.5.9~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.5.9~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.5.9~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.5.9~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.5.9~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.5.9~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~1.5.1~4.el3", rls:"CentOS3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}