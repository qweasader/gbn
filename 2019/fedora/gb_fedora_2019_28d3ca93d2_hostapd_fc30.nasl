# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.876469");
  script_version("2023-10-27T16:11:32+0000");
  script_cve_id("CVE-2019-11555", "CVE-2019-9494", "CVE-2019-9495", "CVE-2019-9496", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-22 17:15:00 +0000 (Thu, 22 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-06-07 02:13:59 +0000 (Fri, 07 Jun 2019)");
  script_name("Fedora Update for hostapd FEDORA-2019-28d3ca93d2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"FEDORA", value:"2019-28d3ca93d2");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IQ6P2GI5GSXRNLNIUNPARFZQVDEIGVZD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hostapd'
  package(s) announced via the FEDORA-2019-28d3ca93d2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"hostapd is a user space daemon for access point and authentication servers. It
implements IEEE 802.11 access point management, IEEE 802.1X/WPA/WPA2/EAP
Authenticators and RADIUS authentication server.

hostapd is designed to be a 'daemon' program that runs in the back-ground and
acts as the backend component controlling authentication. hostapd supports
separate frontend programs and an example text-based frontend, hostapd_cli, is
included with hostapd.");

  script_tag(name:"affected", value:"'hostapd' package(s) on Fedora 30.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC30") {

  if(!isnull(res = isrpmvuln(pkg:"hostapd", rpm:"hostapd~2.8~1.fc30", rls:"FC30"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);