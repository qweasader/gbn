# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.702891");
  script_cve_id("CVE-2013-2031", "CVE-2013-2032", "CVE-2013-4567", "CVE-2013-4568", "CVE-2013-4572", "CVE-2013-6452", "CVE-2013-6453", "CVE-2013-6454", "CVE-2013-6472", "CVE-2014-1610", "CVE-2014-2665");
  script_tag(name:"creation_date", value:"2014-03-29 23:00:00 +0000 (Sat, 29 Mar 2014)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-10 19:40:00 +0000 (Mon, 10 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-2891)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2891");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2891");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2891");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mediawiki, mediawiki-extensions' package(s) announced via the DSA-2891 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in MediaWiki, a wiki engine. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2013-2031

Cross-site scripting attack via valid UTF-7 encoded sequences in a SVG file.

CVE-2013-4567 & CVE-2013-4568 Kevin Israel (Wikipedia user PleaseStand) reported two ways to inject Javascript due to an incomplete blacklist in the CSS sanitizer function.

CVE-2013-4572

MediaWiki and the CentralNotice extension were incorrectly setting cache headers when a user was autocreated, causing the user's session cookies to be cached, and returned to other users.

CVE-2013-6452

Chris from RationalWiki reported that SVG files could be uploaded that include external stylesheets, which could lead to XSS when an XSL was used to include JavaScript.

CVE-2013-6453

MediaWiki's SVG sanitization could be bypassed when the XML was considered invalid.

CVE-2013-6454

MediaWiki's CSS sanitization did not filter -o-link attributes, which could be used to execute JavaScript in Opera 12.

CVE-2013-6472

MediaWiki displayed some information about deleted pages in the log API, enhanced RecentChanges, and user watchlists.

CVE-2014-1610

A remote code execution vulnerability existed if file upload support for DjVu (natively handled) or PDF files (in combination with the PdfHandler extension) was enabled. Neither file type is enabled by default in MediaWiki.

CVE-2014-2665

Cross site request forgery in login form: an attacker could login a victim as the attacker.

For the stable distribution (wheezy), these problems have been fixed in version 1:1.19.14+dfsg-0+deb7u1 of the mediawiki package and 3.5~deb7u1 of the mediawiki-extensions package.

For the unstable distribution (sid), these problems have been fixed in version 1:1.19.14+dfsg-1 of the mediawiki package and 3.5 of the mediawiki-extensions package.

We recommend that you upgrade your mediawiki packages.");

  script_tag(name:"affected", value:"'mediawiki, mediawiki-extensions' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki-extensions-base", ver:"3.5~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki-extensions-collection", ver:"3.5~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki-extensions-confirmedit", ver:"3.5~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki-extensions-geshi", ver:"3.5~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki-extensions-graphviz", ver:"3.5~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki-extensions-ldapauth", ver:"3.5~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki-extensions-openid", ver:"3.5~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki-extensions", ver:"3.5~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki", ver:"1:1.19.14+dfsg-0+deb7u1", rls:"DEB7"))) {
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