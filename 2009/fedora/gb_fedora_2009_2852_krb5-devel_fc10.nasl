# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-2852 (krb5)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63778");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
  script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-2852 (krb5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

This update incorporates patches to fix potential read overflow and NULL pointer
dereferences in the implementation of the SPNEGO GSSAPI mechanism
(CVE-2009-0844, CVE-2009-0845), attempts to free an uninitialized pointer during
protocol parsing (CVE-2009-0846), and a bug in length validation during protocol
parsing (CVE-2009-0847).

ChangeLog:

  * Tue Apr  7 2009 Nalin Dahyabhai  1.6.3-18

  - add patches for read overflow and null pointer dereference in the
implementation of the SPNEGO mechanism (CVE-2009-0844, CVE-2009-0845)

  - add patch for attempt to free uninitialized pointer in libkrb5
(CVE-2009-0846)

  - add patch to fix length validation bug in libkrb5 (CVE-2009-0847)

  * Tue Mar 17 2009 Nalin Dahyabhai  1.6.3-17

  - libgssapi_krb5: backport fix for some errors which can occur when
we fail to set up the server half of a context (CVE-2009-0845)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update krb5' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2852");
  script_tag(name:"summary", value:"The remote host is missing an update to krb5
announced via advisory FEDORA-2009-2852.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490634");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=491033");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=491036");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=491034");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.3~18.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.6.3~18.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-pkinit-openssl", rpm:"krb5-pkinit-openssl~1.6.3~18.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.3~18.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.6.3~18.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.3~18.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-workstation-clients", rpm:"krb5-workstation-clients~1.6.3~18.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-workstation-servers", rpm:"krb5-workstation-servers~1.6.3~18.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.6.3~18.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
