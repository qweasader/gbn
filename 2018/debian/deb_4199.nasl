# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704199");
  script_cve_id("CVE-2018-5150", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5157", "CVE-2018-5158", "CVE-2018-5159", "CVE-2018-5168", "CVE-2018-5178", "CVE-2018-5183");
  script_tag(name:"creation_date", value:"2018-05-09 22:00:00 +0000 (Wed, 09 May 2018)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-13 13:24:00 +0000 (Wed, 13 Mar 2019)");

  script_name("Debian: Security Advisory (DSA-4199)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4199");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4199");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4199");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/firefox-esr");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firefox-esr' package(s) announced via the DSA-4199 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been found in the Mozilla Firefox web browser: Multiple memory safety errors and other implementation errors may lead to the execution of arbitrary code or denial of service.

For the oldstable distribution (jessie), these problems have been fixed in version 52.8.0esr-1~deb8u1.

For the stable distribution (stretch), these problems have been fixed in version 52.8.0esr-1~deb9u1.

We recommend that you upgrade your firefox-esr packages.

For the detailed security status of firefox-esr please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'firefox-esr' package(s) on Debian 8, Debian 9.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-dbg", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-dev", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ach", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-af", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-all", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-an", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ar", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-as", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ast", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-az", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bg", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bn-bd", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bn-in", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-br", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bs", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ca", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cak", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cs", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cy", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-da", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-de", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-dsb", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-el", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-en-gb", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-en-za", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-eo", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-ar", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-cl", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-es", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-mx", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-et", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-eu", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fa", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ff", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fi", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fr", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fy-nl", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ga-ie", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gd", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gl", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gn", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gu-in", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-he", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hi-in", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hr", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hsb", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hu", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hy-am", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-id", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-is", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-it", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ja", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ka", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kab", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kk", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-km", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kn", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ko", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lij", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lt", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lv", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mai", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mk", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ml", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mr", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ms", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nb-no", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nl", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nn-no", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-or", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pa-in", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pl", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-br", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-pt", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-rm", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ro", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ru", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-si", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sk", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sl", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-son", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sq", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sr", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sv-se", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ta", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-te", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-th", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-tr", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-uk", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-uz", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-vi", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-xh", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-cn", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-tw", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dev", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ach", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-af", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-all", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-an", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ar", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-as", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ast", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-az", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bg", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bn-bd", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bn-in", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-br", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bs", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ca", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cak", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cs", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cy", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-da", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-de", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-dsb", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-el", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-en-gb", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-en-za", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-eo", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-ar", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-cl", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-es", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-mx", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-et", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-eu", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fa", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ff", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fi", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fr", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fy-nl", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ga-ie", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gd", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gl", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gn", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gu-in", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-he", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hi-in", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hr", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hsb", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hu", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hy-am", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-id", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-is", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-it", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ja", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ka", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kab", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kk", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-km", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kn", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ko", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lij", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lt", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lv", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-mai", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-mk", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ml", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-mr", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ms", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nb-no", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nl", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nn-no", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-or", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pa-in", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pl", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pt-br", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pt-pt", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-rm", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ro", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ru", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-si", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sk", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sl", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-son", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sq", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sr", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sv-se", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ta", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-te", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-th", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-tr", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-uk", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-uz", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-vi", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-xh", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-zh-cn", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-zh-tw", ver:"1:52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel", ver:"52.8.0esr-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-dev", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ach", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-af", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-all", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-an", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ar", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-as", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ast", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-az", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bg", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bn-bd", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bn-in", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-br", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bs", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ca", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cak", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cs", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cy", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-da", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-de", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-dsb", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-el", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-en-gb", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-en-za", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-eo", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-ar", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-cl", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-es", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-mx", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-et", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-eu", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fa", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ff", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fi", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fr", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fy-nl", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ga-ie", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gd", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gl", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gn", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gu-in", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-he", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hi-in", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hr", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hsb", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hu", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hy-am", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-id", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-is", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-it", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ja", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ka", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kab", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kk", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-km", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kn", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ko", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lij", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lt", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lv", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mai", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mk", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ml", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mr", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ms", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nb-no", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nl", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nn-no", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-or", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pa-in", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pl", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-br", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-pt", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-rm", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ro", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ru", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-si", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sk", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sl", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-son", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sq", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sr", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sv-se", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ta", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-te", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-th", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-tr", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-uk", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-uz", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-vi", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-xh", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-cn", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-tw", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dev", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ach", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-af", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-all", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-an", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ar", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-as", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ast", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-az", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bg", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bn-bd", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bn-in", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-br", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bs", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ca", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cak", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cs", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cy", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-da", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-de", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-dsb", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-el", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-en-gb", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-en-za", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-eo", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-ar", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-cl", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-es", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-mx", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-et", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-eu", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fa", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ff", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fi", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fr", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fy-nl", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ga-ie", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gd", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gl", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gn", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gu-in", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-he", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hi-in", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hr", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hsb", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hu", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hy-am", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-id", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-is", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-it", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ja", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ka", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kab", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kk", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-km", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kn", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ko", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lij", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lt", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lv", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-mai", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-mk", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ml", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-mr", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ms", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nb-no", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nl", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nn-no", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-or", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pa-in", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pl", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pt-br", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pt-pt", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-rm", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ro", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ru", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-si", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sk", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sl", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-son", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sq", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sr", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sv-se", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ta", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-te", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-th", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-tr", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-uk", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-uz", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-vi", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-xh", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-zh-cn", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-zh-tw", ver:"1:52.8.0esr-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel", ver:"52.8.0esr-1~deb9u1", rls:"DEB9"))) {
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
