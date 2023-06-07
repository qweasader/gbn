# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-8812 (httpd)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64741");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-1891", "CVE-2009-1195", "CVE-2009-1890", "CVE-2009-1191");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("Fedora Core 11 FEDORA-2009-8812 (httpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"The Apache HTTP Server is a powerful, efficient, and extensible
web server.

Update Information:

This update includes the latest release of the Apache HTTP Server, version
2.2.13, fixing several security issues:

  * Fix a potential Denial-of-Service attack against mod_deflate or
  other modules, by forcing the server to consume CPU time in compressing
  a large file after a client disconnects.  (CVE-2009-1891)

  * Prevent the Includes Option from being enabled in an
  .htaccess file if the AllowOverride restrictions do not permit it.
  (CVE-2009-1195)

  * Fix a potential Denial-of-Service attack against mod_proxy
  in a reverse proxy configuration, where a remote attacker can force a proxy
  process to consume CPU time indefinitely. (CVE-2009-1890)

  * mod_proxy_ajp: Avoid delivering content from a previous request
  which failed to send a request body.  (CVE-2009-1191)

Many bug fixes are also included.

ChangeLog:

  * Tue Aug 18 2009 Joe Orton  2.2.13-1

  - update to 2.2.13");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update httpd' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8812");
  script_tag(name:"summary", value:"The remote host is missing an update to httpd
announced via advisory FEDORA-2009-8812.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=509375");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=509125");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=489436");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.13~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.13~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.13~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.2.13~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.13~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.2.13~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
