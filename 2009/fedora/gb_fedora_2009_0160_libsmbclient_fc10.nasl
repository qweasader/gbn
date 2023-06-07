# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-0160 (samba)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63122");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-01-07 23:16:01 +0100 (Wed, 07 Jan 2009)");
  script_cve_id("CVE-2009-0022", "CVE-2008-4314");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:P");
  script_name("Fedora Core 10 FEDORA-2009-0160 (samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

Security fix for CVE-2009-0022

ChangeLog:

  * Mon Jan  5 2009 Guenther Deschner  - 3.2.7-0.25

  - Update to 3.2.7 (Security fix for CVE-2009-0022)

  * Wed Dec 10 2008 Guenther Deschner  - 3.2.6-0.24

  - Update to 3.2.6

  * Thu Nov 27 2008 Guenther Deschner  - 3.2.5-0.23

  - Update to 3.2.5 (Security fix for CVE-2008-4314)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update samba' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0160");
  script_tag(name:"summary", value:"The remote host is missing an update to samba
announced via advisory FEDORA-2009-0160.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.2.7~0.25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~3.2.7~0.25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtalloc", rpm:"libtalloc~1.2.0~25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtalloc-devel", rpm:"libtalloc-devel~1.2.0~25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtdb", rpm:"libtdb~1.1.1~25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtdb-devel", rpm:"libtdb-devel~1.1.1~25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.2.7~0.25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.2.7~0.25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.2.7~0.25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.2.7~0.25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-domainjoin-gui", rpm:"samba-domainjoin-gui~3.2.7~0.25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.2.7~0.25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.2.7~0.25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-winbind-devel", rpm:"samba-winbind-devel~3.2.7~0.25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tdb-tools", rpm:"tdb-tools~1.1.1~25.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~3.2.7~0.25.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
