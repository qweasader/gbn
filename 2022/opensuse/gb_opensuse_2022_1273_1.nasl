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
  script_oid("1.3.6.1.4.1.25623.1.0.854621");
  script_version("2023-10-19T05:05:21+0000");
  script_cve_id("CVE-2020-14409", "CVE-2020-14410", "CVE-2021-33657");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-12 17:49:00 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-05-17 12:05:49 +0000 (Tue, 17 May 2022)");
  script_name("openSUSE: Security Advisory for SDL (SUSE-SU-2022:1273-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1273-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GCTOZ6PYY7RHFKQZCR36S4INP2QDEWSL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SDL'
  package(s) announced via the SUSE-SU-2022:1273-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for SDL fixes the following issues:

  - CVE-2020-14409: Fixed an integer overflow (and resultant SDL_memcpy heap
       corruption) in SDL_BlitCopy in video/SDL_blit_copy.c. (bsc#1181202)

  - CVE-2020-14410: Fixed a heap-based buffer over-read in
       Blit_3or4_to_3or4__inversed_rgb in video/SDL_blit_N.c. (bsc#1181201)

  - CVE-2021-33657: Fixed a Heap overflow problem in video/SDL_pixels.c.
       (bsc#1198001)");

  script_tag(name:"affected", value:"'SDL' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"SDL-debugsource", rpm:"SDL-debugsource~1.2.15~150000.3.19.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0", rpm:"libSDL-1_2-0~1.2.15~150000.3.19.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-debuginfo", rpm:"libSDL-1_2-0-debuginfo~1.2.15~150000.3.19.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-devel", rpm:"libSDL-devel~1.2.15~150000.3.19.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-32bit", rpm:"libSDL-1_2-0-32bit~1.2.15~150000.3.19.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-32bit-debuginfo", rpm:"libSDL-1_2-0-32bit-debuginfo~1.2.15~150000.3.19.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-devel-32bit", rpm:"libSDL-devel-32bit~1.2.15~150000.3.19.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"SDL-debugsource", rpm:"SDL-debugsource~1.2.15~150000.3.19.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0", rpm:"libSDL-1_2-0~1.2.15~150000.3.19.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-debuginfo", rpm:"libSDL-1_2-0-debuginfo~1.2.15~150000.3.19.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-devel", rpm:"libSDL-devel~1.2.15~150000.3.19.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-32bit", rpm:"libSDL-1_2-0-32bit~1.2.15~150000.3.19.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-32bit-debuginfo", rpm:"libSDL-1_2-0-32bit-debuginfo~1.2.15~150000.3.19.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-devel-32bit", rpm:"libSDL-devel-32bit~1.2.15~150000.3.19.1", rls:"openSUSELeap15.3"))) {
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