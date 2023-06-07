# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-2419 (knetworkmanager)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63527");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-03-13 19:24:56 +0100 (Fri, 13 Mar 2009)");
  script_cve_id("CVE-2009-0365", "CVE-2009-0578");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-2419 (knetworkmanager)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"ChangeLog:

  * Tue Mar  3 2009 Dan Williams  - 0.7-0.8.20080926svn

  - don't send blank passwords in settings (rh #486877)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update knetworkmanager' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2419");
  script_tag(name:"summary", value:"The remote host is missing an update to knetworkmanager
announced via advisory FEDORA-2009-2419.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=487722");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=487752");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"knetworkmanager", rpm:"knetworkmanager~0.7~0.8.20080926svn.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"knetworkmanager-devel", rpm:"knetworkmanager-devel~0.7~0.8.20080926svn.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"knetworkmanager-openvpn", rpm:"knetworkmanager-openvpn~0.7~0.8.20080926svn.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"knetworkmanager-pptp", rpm:"knetworkmanager-pptp~0.7~0.8.20080926svn.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"knetworkmanager-vpnc", rpm:"knetworkmanager-vpnc~0.7~0.8.20080926svn.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"knetworkmanager-debuginfo", rpm:"knetworkmanager-debuginfo~0.7~0.8.20080926svn.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
