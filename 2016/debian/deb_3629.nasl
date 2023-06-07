# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.703629");
  script_cve_id("CVE-2015-7974", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8158", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1550", "CVE-2016-2516", "CVE-2016-2518");
  script_tag(name:"creation_date", value:"2016-08-02 05:26:41 +0000 (Tue, 02 Aug 2016)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-26 17:42:00 +0000 (Mon, 26 Apr 2021)");

  script_name("Debian: Security Advisory (DSA-3629)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3629");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3629");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3629");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ntp' package(s) announced via the DSA-3629 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Network Time Protocol daemon and utility programs:

CVE-2015-7974

Matt Street discovered that insufficient key validation allows impersonation attacks between authenticated peers.

CVE-2015-7977

CVE-2015-7978

Stephen Gray discovered that a NULL pointer dereference and a buffer overflow in the handling of ntpdc reslist commands may result in denial of service.

CVE-2015-7979

Aanchal Malhotra discovered that if NTP is configured for broadcast mode, an attacker can send malformed authentication packets which break associations with the server for other broadcast clients.

CVE-2015-8138

Matthew van Gundy and Jonathan Gardner discovered that missing validation of origin timestamps in ntpd clients may result in denial of service.

CVE-2015-8158

Jonathan Gardner discovered that missing input sanitising in ntpq may result in denial of service.

CVE-2016-1547

Stephen Gray and Matthew van Gundy discovered that incorrect handling of crypto NAK packets may result in denial of service.

CVE-2016-1548

Jonathan Gardner and Miroslav Lichvar discovered that ntpd clients could be forced to change from basic client/server mode to interleaved symmetric mode, preventing time synchronisation.

CVE-2016-1550

Matthew van Gundy, Stephen Gray and Loganaden Velvindron discovered that timing leaks in the packet authentication code could result in recovery of a message digest.

CVE-2016-2516

Yihan Lian discovered that duplicate IPs on unconfig directives will trigger an assert.

CVE-2016-2518

Yihan Lian discovered that an OOB memory access could potentially crash ntpd.

For the stable distribution (jessie), these problems have been fixed in version 1:4.2.6.p5+dfsg-7+deb8u2.

For the testing distribution (stretch), these problems have been fixed in version 1:4.2.8p7+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 1:4.2.8p7+dfsg-1.

We recommend that you upgrade your ntp packages.");

  script_tag(name:"affected", value:"'ntp' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.6.p5+dfsg-7+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-7+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.6.p5+dfsg-7+deb8u2", rls:"DEB8"))) {
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
