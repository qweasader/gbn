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
  script_oid("1.3.6.1.4.1.25623.1.0.851425");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-11-05 05:31:43 +0100 (Sat, 05 Nov 2016)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-5198");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2016:2733-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update to Chromium 54.0.2840.90: fixes the following security issues:

  - CVE-2016-5198: out of bounds memory access in v8 (boo#1008274)");

  script_tag(name:"affected", value:"chromium on openSUSE Leap 42.1, openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:2733-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2")
{

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~54.0.2840.90~134.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~54.0.2840.90~134.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~54.0.2840.90~134.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~54.0.2840.90~134.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~54.0.2840.90~134.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~54.0.2840.90~134.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~54.0.2840.90~134.1", rls:"openSUSE13.2"))) {
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
