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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0403");
  script_cve_id("CVE-2016-5181", "CVE-2016-5182", "CVE-2016-5183", "CVE-2016-5184", "CVE-2016-5185", "CVE-2016-5186", "CVE-2016-5187", "CVE-2016-5188", "CVE-2016-5189", "CVE-2016-5190", "CVE-2016-5191", "CVE-2016-5192", "CVE-2016-5193", "CVE-2016-5194", "CVE-2016-5198", "CVE-2016-5199", "CVE-2016-5200", "CVE-2016-5201", "CVE-2016-5202");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-21 13:04:00 +0000 (Thu, 21 Nov 2019)");

  script_name("Mageia: Security Advisory (MGASA-2016-0403)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0403");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0403.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19582");
  script_xref(name:"URL", value:"https://googlechromereleases.blogspot.com/2016/10/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://googlechromereleases.blogspot.com/2016/10/stable-channel-update-for-desktop_20.html");
  script_xref(name:"URL", value:"https://googlechromereleases.blogspot.com/2016/11/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://googlechromereleases.blogspot.com/2016/11/stable-channel-update-for-desktop_9.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2016-0403 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws were found in Chromium's processing of web content where
loading a web page containing malicious content could cause Chromium to
crash, execute arbitrary code, or disclose sensitive information.
(CVE-2016-5181, CVE-2016-5182, CVE-2016-5183, CVE-2016-5184,
CVE-2016-5185, CVE-2016-5186, CVE-2016-5187, CVE-2016-5188,
CVE-2016-5189, CVE-2016-5190, CVE-2016-5191, CVE-2016-5192,
CVE-2016-5193, CVE-2016-5194, CVE-2016-5198, CVE-2016-5199,
CVE-2016-5200, CVE-2016-5201, CVE-2016-5202)");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~54.0.2840.100~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~54.0.2840.100~1.1.mga5", rls:"MAGEIA5"))) {
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
