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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0199");
  script_cve_id("CVE-2016-4476", "CVE-2016-4477");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 13:13:00 +0000 (Wed, 12 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2016-0199)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0199");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0199.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18335");
  script_xref(name:"URL", value:"http://w1.fi/security/2016-1/psk-parameter-config-update.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa_supplicant' package(s) announced via the MGASA-2016-0199 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated wpa_suppliant packages fix security vulnerabilities:

A vulnerability was found in how wpa_supplicant writes the configuration file
update for the WPA/WPA2 passphrase parameter. If this parameter has been
updated to include control characters either through a WPS operation
(CVE-2016-4476) or through local configuration change over the wpa_supplicant
control interface (CVE-2016-4477), the resulting configuration file may prevent
the wpa_supplicant from starting when the updated file is used. In addition, it
may be possible to load a local library file and execute code from there with
the same privileges under which the wpa_supplicant process runs.");

  script_tag(name:"affected", value:"'wpa_supplicant' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.3~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-gui", rpm:"wpa_supplicant-gui~2.3~3.1.mga5", rls:"MAGEIA5"))) {
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
