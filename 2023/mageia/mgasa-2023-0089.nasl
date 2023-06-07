# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0089");
  script_cve_id("CVE-2023-23009");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-28T10:19:28+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:19:28 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-07 20:18:00 +0000 (Tue, 07 Mar 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0089)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0089");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0089.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31636");
  script_xref(name:"URL", value:"https://libreswan.org/security/CVE-2023-23009/CVE-2023-23009.txt");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/CVE-2023-23009");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreswan' package(s) announced via the MGASA-2023-0089 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A change in the libreswan 4.2 Traffic Selector parsing code introduced a
missing check that would reject palformed Traffic Selector payloads. As
such, in such case the code stumbles on to hit a double free, leading to a
crash and restart of the pluto daemon. No remote code execution.
(CVE-2023-23009)");

  script_tag(name:"affected", value:"'libreswan' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"libreswan", rpm:"libreswan~4.6~4.1.mga8", rls:"MAGEIA8"))) {
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
