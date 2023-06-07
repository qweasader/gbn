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
  script_oid("1.3.6.1.4.1.25623.1.0.891386");
  script_cve_id("CVE-2018-7866", "CVE-2018-7873", "CVE-2018-7876", "CVE-2018-9009", "CVE-2018-9132");
  script_tag(name:"creation_date", value:"2018-05-27 22:00:00 +0000 (Sun, 27 May 2018)");
  script_version("2023-03-09T10:20:43+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:43 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-12 03:15:00 +0000 (Sat, 12 Oct 2019)");

  script_name("Debian: Security Advisory (DLA-1386)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1386");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1386");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ming' package(s) announced via the DLA-1386 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Ming:

CVE-2018-7866

NULL pointer dereference in the newVar3 function (util/decompile.c). Remote attackers might leverage this vulnerability to cause a denial of service via a crafted swf file.

CVE-2018-7873

Heap-based buffer overflow vulnerability in the getString function (util/decompile.c). Remote attackers might leverage this vulnerability to cause a denial of service via a crafted swf file.

CVE-2018-7876

Integer overflow and resulting memory exhaustion in the parseSWF_ACTIONRECORD function (util/parser.c). Remote attackers might leverage this vulnerability to cause a denial of service via a crafted swf file.

CVE-2018-9009

Various heap-based buffer overflow vulnerabilities in util/decompiler.c. Remote attackers might leverage this vulnerability to cause a denial of service via a crafted swf file.

CVE-2018-9132

NULL pointer dereference in the getInt function (util/decompile.c). Remote attackers might leverage this vulnerability to cause a denial of service via a crafted swf file.

For Debian 7 Wheezy, these problems have been fixed in version 1:0.4.4-1.1+deb7u9.

We recommend that you upgrade your ming packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ming' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libming-dev", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libming-util", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libming1", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswf-perl", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ming-fonts-dejavu", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ming-fonts-opensymbol", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-ming", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-ming", ver:"1:0.4.4-1.1+deb7u9", rls:"DEB7"))) {
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
