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
  script_oid("1.3.6.1.4.1.25623.1.0.891525");
  script_cve_id("CVE-2017-7653", "CVE-2017-7654", "CVE-2017-9868");
  script_tag(name:"creation_date", value:"2018-09-30 22:00:00 +0000 (Sun, 30 Sep 2018)");
  script_version("2023-03-09T10:20:43+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:43 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DLA-1525)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1525");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1525");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mosquitto' package(s) announced via the DLA-1525 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2017-7653

As invalid UTF-8 strings are not correctly checked, an attacker could cause a denial of service to other clients by disconnecting them from the broker with special crafted topics.

CVE-2017-7654

Due to a memory leak unauthenticated clients can send special crafted CONNECT packets which could cause a denial of service in the broker.

CVE-2017-9868

Due to wrong file permissions local users could obtain topic information from the mosquitto database.

For Debian 8 Jessie, these problems have been fixed in version 1.3.4-2+deb8u3.

We recommend that you upgrade your mosquitto packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mosquitto' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmosquitto-dev", ver:"1.3.4-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmosquitto1", ver:"1.3.4-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmosquittopp-dev", ver:"1.3.4-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmosquittopp1", ver:"1.3.4-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mosquitto-clients", ver:"1.3.4-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mosquitto-dbg", ver:"1.3.4-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mosquitto", ver:"1.3.4-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-mosquitto", ver:"1.3.4-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-mosquitto", ver:"1.3.4-2+deb8u3", rls:"DEB8"))) {
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
