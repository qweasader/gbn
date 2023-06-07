# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory FEDORA-2009-1204 (roundcubemail)
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
  script_oid("1.3.6.1.4.1.25623.1.0.63323");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-02-10 15:52:40 +0100 (Tue, 10 Feb 2009)");
  script_cve_id("CVE-2009-0413");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 10 FEDORA-2009-1204 (roundcubemail)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

Security fix for:
Common Vulnerabilities and Exposures assigned an identifier
CVE-2009-0413 to  the following vulnerability:
Cross-site scripting (XSS) vulnerability in RoundCube Webmail
(roundcubemail) 0.2 stable allows remote attackers to inject
arbitrary  web script or HTML via the background attribute
embedded in an HTML e-mail message.

ChangeLog:

  * Wed Feb  4 2009 Jon Ciesla  = 0.2-7.stable

  - Patch for CVE-2009-0413, BZ 484052.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update roundcubemail' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1204");
  script_tag(name:"summary", value:"The remote host is missing an update to roundcubemail
announced via advisory FEDORA-2009-1204.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484052");
  script_xref(name:"URL", value:"http://trac.roundcube.net/changeset/2245");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33372");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33622");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48129");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~0.2~7.stable.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
