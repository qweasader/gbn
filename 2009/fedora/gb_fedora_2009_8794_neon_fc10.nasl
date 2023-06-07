# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-8794 (neon)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64713");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-2473");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 10 FEDORA-2009-8794 (neon)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

This update includes the latest release of neon, version 0.28.6.
This fixes two security issues:

  * the billion laughs attack against expat could allow a Denial
  of Service attack by a malicious server.  (CVE-2009-2473)

  * an embedded NUL byte in a certificate subject name could allow
  an undetected MITM attack against an SSL server if a trusted CA
  issues such a cert.

Several bug fixes are also included, notably:

  * X.509v1 CA certificates are trusted by default

  * Fix handling of some PKCS#12 certificates

ChangeLog:

  * Wed Aug 19 2009 Joe Orton  0.28.6-1

  - update to 0.28.6

  * Fri May 29 2009 Joe Orton  0.28.4-1.1

  - trust V1 CA certs by default (#502451)

  * Fri Mar  6 2009 Joe Orton  0.28.4-1

  - update to 0.28.4

  * Mon Jan 19 2009 Joe Orton  0.28.3-3

  - use install-p in make install (Robert Scheck, #226189)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update neon' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8794");
  script_tag(name:"summary", value:"The remote host is missing an update to neon
announced via advisory FEDORA-2009-8794.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502451");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"neon", rpm:"neon~0.28.6~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"neon-devel", rpm:"neon-devel~0.28.6~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"neon-debuginfo", rpm:"neon-debuginfo~0.28.6~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
