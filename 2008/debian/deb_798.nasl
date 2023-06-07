# Copyright (C) 2008 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55208");
  script_cve_id("CVE-2005-2498", "CVE-2005-2600", "CVE-2005-2761");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-798)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-798");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-798");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-798");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpgroupware' package(s) announced via the DSA-798 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in phpgroupware, a web based groupware system written in PHP. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-2498

Stefan Esser discovered another vulnerability in the XML-RPC libraries that allows injection of arbitrary PHP code into eval() statements. The XMLRPC component has been disabled.

CAN-2005-2600

Alexander Heidenreich discovered a cross-site scripting problem in the tree view of FUD Forum Bulletin Board Software, which is also present in phpgroupware.

CAN-2005-2761

A global cross-site scripting fix has also been included that protects against potential malicious scripts embedded in CSS and xmlns in various parts of the application and modules.

This update also contains a postinst bugfix that has been approved for the next update to the stable release.

For the old stable distribution (woody) these problems don't apply.

For the stable distribution (sarge) these problems have been fixed in version 0.9.16.005-3.sarge2.

For the unstable distribution (sid) these problems have been fixed in version 0.9.16.008.

We recommend that you upgrade your phpgroupware packages.");

  script_tag(name:"affected", value:"'phpgroupware' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-addressbook", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-admin", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-bookmarks", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-calendar", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-chat", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-comic", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-core", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-developer-tools", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-dj", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-eldaptir", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-email", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-etemplate", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-felamimail", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-filemanager", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-folders", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-forum", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-ftp", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-fudforum", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-headlines", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-hr", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-img", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-infolog", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-manual", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-messenger", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-news-admin", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-nntp", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-notes", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phonelog", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phpbrain", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phpgwapi", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phpsysinfo", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-polls", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-preferences", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-projects", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-qmailldap", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-registration", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-setup", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-sitemgr", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-skel", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-soap", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-stocks", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-todo", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-tts", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-wiki", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-xmlrpc", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware", ver:"0.9.16.005-3.sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
