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
  script_oid("1.3.6.1.4.1.25623.1.0.891243");
  script_cve_id("CVE-2017-8314");
  script_tag(name:"creation_date", value:"2018-01-15 23:00:00 +0000 (Mon, 15 Jan 2018)");
  script_version("2023-03-09T10:20:43+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:43 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DLA-1243)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1243");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1243");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xbmc' package(s) announced via the DLA-1243 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Check Point Research Team discovered that the XBMC media center allows arbitrary file write when a malicious subtitle file is downloaded in zip format. This update requires the new dependency libboost-regex1.49.

For Debian 7 Wheezy, these problems have been fixed in version 2:11.0~git20120510.82388d5-1+deb7u1.

We recommend that you upgrade your xbmc packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'xbmc' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xbmc-bin", ver:"2:11.0~git20120510.82388d5-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xbmc-data", ver:"2:11.0~git20120510.82388d5-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xbmc-eventclients-common", ver:"2:11.0~git20120510.82388d5-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xbmc-eventclients-dev", ver:"2:11.0~git20120510.82388d5-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xbmc-eventclients-j2me", ver:"2:11.0~git20120510.82388d5-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xbmc-eventclients-ps3", ver:"2:11.0~git20120510.82388d5-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xbmc-eventclients-wiiremote", ver:"2:11.0~git20120510.82388d5-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xbmc-eventclients-xbmc-send", ver:"2:11.0~git20120510.82388d5-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xbmc-skin-confluence", ver:"2:11.0~git20120510.82388d5-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xbmc-standalone", ver:"2:11.0~git20120510.82388d5-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xbmc", ver:"2:11.0~git20120510.82388d5-1+deb7u1", rls:"DEB7"))) {
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
