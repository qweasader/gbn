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
  script_oid("1.3.6.1.4.1.25623.1.0.61366");
  script_cve_id("CVE-2008-2785", "CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2811", "CVE-2008-2933");
  script_tag(name:"creation_date", value:"2008-08-15 13:52:52 +0000 (Fri, 15 Aug 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1615)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1615");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1615");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1615");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-1615 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-2785

It was discovered that missing boundary checks on a reference counter for CSS objects can lead to the execution of arbitrary code.

CVE-2008-2798

Devon Hubbard, Jesse Ruderman and Martijn Wargers discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2008-2799

Igor Bukanov, Jesse Ruderman and Gary Kwong discovered crashes in the Javascript engine, which might allow the execution of arbitrary code.

CVE-2008-2800

moz_bug_r_a4 discovered several cross-site scripting vulnerabilities.

CVE-2008-2801

Collin Jackson and Adam Barth discovered that Javascript code could be executed in the context of signed JAR archives.

CVE-2008-2802

moz_bug_r_a4 discovered that XUL documents can escalate privileges by accessing the pre-compiled fastload file.

CVE-2008-2803

moz_bug_r_a4 discovered that missing input sanitising in the mozIJSSubScriptLoader.loadSubScript() function could lead to the execution of arbitrary code. Iceweasel itself is not affected, but some addons are.

CVE-2008-2805

Claudio Santambrogio discovered that missing access validation in DOM parsing allows malicious web sites to force the browser to upload local files to the server, which could lead to information disclosure.

CVE-2008-2807

Daniel Glazman discovered that a programming error in the code for parsing .properties files could lead to memory content being exposed to addons, which could lead to information disclosure.

CVE-2008-2808

Masahiro Yamada discovered that file URLs in directory listings were insufficiently escaped.

CVE-2008-2809

John G. Myers, Frank Benkstein and Nils Toedtmann discovered that alternate names on self-signed certificates were handled insufficiently, which could lead to spoofing of secure connections.

CVE-2008-2811

Greg McManus discovered a crash in the block reflow code, which might allow the execution of arbitrary code.

CVE-2008-2933

Billy Rios discovered that passing an URL containing a pipe symbol to Iceweasel can lead to Chrome privilege escalation.

For the stable distribution (etch), these problems have been fixed in version 1.8.0.15~pre080614d-0etch1.

For the unstable distribution (sid), these problems have been fixed in version 1.9.0.1-1.

We recommend that you upgrade your xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs0d-dbg", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs0d", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4-0d-dbg", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4-0d", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4-dev", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-0d-dbg", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-0d", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-dev", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-tools", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmjs-dev", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmjs1", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxul-common", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxul-dev", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxul0d-dbg", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxul0d", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-xpcom", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-gnome-support", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner", ver:"1.8.0.15~pre080614d-0etch1", rls:"DEB4"))) {
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
