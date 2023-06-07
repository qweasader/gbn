# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.705211");
  script_cve_id("CVE-2022-32792", "CVE-2022-32816", "CVE-2022-32891");
  script_tag(name:"creation_date", value:"2022-08-18 01:00:05 +0000 (Thu, 18 Aug 2022)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-27 19:32:00 +0000 (Tue, 27 Sep 2022)");

  script_name("Debian: Security Advisory (DSA-5211)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5211");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5211");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5211");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wpewebkit");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wpewebkit' package(s) announced via the DSA-5211 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been discovered in the WPE WebKit web engine:

CVE-2022-32792

Manfred Paul discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2022-32816

Dohyun Lee discovered that visiting a website that frames malicious content may lead to UI spoofing.

For the stable distribution (bullseye), these problems have been fixed in version 2.36.6-1~deb11u1.

We recommend that you upgrade your wpewebkit packages.

For the detailed security status of wpewebkit please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wpewebkit' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-3", ver:"2.36.6-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-dev", ver:"2.36.6-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-doc", ver:"2.36.6-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpewebkit-driver", ver:"2.36.6-1~deb11u1", rls:"DEB11"))) {
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
