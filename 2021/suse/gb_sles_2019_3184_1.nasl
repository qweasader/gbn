# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3184.1");
  script_cve_id("CVE-2018-13301", "CVE-2019-12730", "CVE-2019-17542", "CVE-2019-9718");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-07 17:06:00 +0000 (Wed, 07 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3184-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3184-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193184-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the SUSE-SU-2019:3184-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg fixes the following issues:

Security issues fixed:
CVE-2019-17542: Fixed a heap-buffer overflow in vqa_decode_chunk due to
 an
 out-of-array access (bsc#1154064).

CVE-2019-12730: Fixed an uninitialized use of variables due to an
 improper check (bsc#1137526).

CVE-2019-9718: Fixed a denial of service in the subtitle decode
 (bsc#1129715).

CVE-2018-13301: Fixed a denial of service while converting a crafted AVI
 file to MPEG4 (bsc#1100352).");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Desktop Applications 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Module for Packagehub Subpackages 15, SUSE Linux Enterprise Workstation Extension 15, SUSE Linux Enterprise Workstation Extension 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-debuginfo", rpm:"libavcodec57-debuginfo~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-debuginfo", rpm:"libavutil55-debuginfo~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-debuginfo", rpm:"libpostproc54-debuginfo~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-debuginfo", rpm:"libswresample2-debuginfo~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-debuginfo", rpm:"libswscale4-debuginfo~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57", rpm:"libavdevice57~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57-debuginfo", rpm:"libavdevice57-debuginfo~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6", rpm:"libavfilter6~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6-debuginfo", rpm:"libavfilter6-debuginfo~3.4.2~4.27.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-debuginfo", rpm:"libavcodec57-debuginfo~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-debuginfo", rpm:"libavutil55-debuginfo~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-debuginfo", rpm:"libpostproc54-debuginfo~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-debuginfo", rpm:"libswresample2-debuginfo~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-debuginfo", rpm:"libswscale4-debuginfo~3.4.2~4.27.1", rls:"SLES15.0SP1"))) {
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
