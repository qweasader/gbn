# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory RHSA-2009:0410 ()
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
  script_oid("1.3.6.1.4.1.25623.1.0.63761");
  script_version("2022-01-21T08:36:19+0000");
  script_tag(name:"last_modification", value:"2022-01-21 08:36:19 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
  script_cve_id("CVE-2009-0846");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:0410");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(2\.1|3)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0410.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third party, the Key Distribution Center (KDC).

An input validation flaw was found in the ASN.1 (Abstract Syntax Notation
One) decoder used by MIT Kerberos. A remote attacker could use this flaw to
crash a network service using the MIT Kerberos library, such as kadmind or
krb5kdc, by causing it to dereference or free an uninitialized pointer or,
possibly, execute arbitrary code with the privileges of the user running
the service. (CVE-2009-0846)

All krb5 users should upgrade to these updated packages, which contain a
backported patch to correct this issue. All running services using the MIT
Kerberos libraries must be restarted for the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0410.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#critical");
  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2009-002.txt");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.2.2~49", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.2.2~49", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.2.2~49", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.2.2~49", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.2.7~70", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.2.7~70", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.2.7~70", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.2.7~70", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.2.7~70", rls:"RHENT_3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
