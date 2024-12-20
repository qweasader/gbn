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
  script_oid("1.3.6.1.4.1.25623.1.0.854506");
  script_version("2023-10-19T05:05:21+0000");
  script_cve_id("CVE-2022-0284");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-01 19:58:00 +0000 (Thu, 01 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-02-22 02:02:24 +0000 (Tue, 22 Feb 2022)");
  script_name("openSUSE: Security Advisory for ImageMagick (openSUSE-SU-2022:0540-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0540-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZUE6OO6UE5NEQ2LYEJSEB2AXREVWZVMB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the openSUSE-SU-2022:0540-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

  - CVE-2022-0284: Fixed heap buffer overread in GetPixelAlpha() in
       MagickCore/pixel-accessor.h (bsc#1195563).");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI4", rpm:"libMagick++-7_Q16HDRI4~7.0.7.34~10.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI4-debuginfo", rpm:"libMagick++-7_Q16HDRI4-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI6", rpm:"libMagickCore-7_Q16HDRI6~7.0.7.34~10.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI6-debuginfo", rpm:"libMagickCore-7_Q16HDRI6-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI6", rpm:"libMagickWand-7_Q16HDRI6~7.0.7.34~10.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI6-debuginfo", rpm:"libMagickWand-7_Q16HDRI6-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI4-32bit", rpm:"libMagick++-7_Q16HDRI4-32bit~7.0.7.34~10.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI4-32bit-debuginfo", rpm:"libMagick++-7_Q16HDRI4-32bit-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI6-32bit", rpm:"libMagickCore-7_Q16HDRI6-32bit~7.0.7.34~10.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI6-32bit-debuginfo", rpm:"libMagickCore-7_Q16HDRI6-32bit-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI6-32bit", rpm:"libMagickWand-7_Q16HDRI6-32bit~7.0.7.34~10.21.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI6-32bit-debuginfo", rpm:"libMagickWand-7_Q16HDRI6-32bit-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-SUSE", rpm:"ImageMagick-config-7-SUSE~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream", rpm:"ImageMagick-config-7-upstream~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debugsource", rpm:"ImageMagick-debugsource~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-extra-debuginfo", rpm:"ImageMagick-extra-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI4", rpm:"libMagick++-7_Q16HDRI4~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI4-debuginfo", rpm:"libMagick++-7_Q16HDRI4-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI6", rpm:"libMagickCore-7_Q16HDRI6~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI6-debuginfo", rpm:"libMagickCore-7_Q16HDRI6-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI6", rpm:"libMagickWand-7_Q16HDRI6~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI6-debuginfo", rpm:"libMagickWand-7_Q16HDRI6-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PerlMagick-debuginfo", rpm:"perl-PerlMagick-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel-32bit", rpm:"ImageMagick-devel-32bit~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI4-32bit", rpm:"libMagick++-7_Q16HDRI4-32bit~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI4-32bit-debuginfo", rpm:"libMagick++-7_Q16HDRI4-32bit-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel-32bit", rpm:"libMagick++-devel-32bit~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI6-32bit", rpm:"libMagickCore-7_Q16HDRI6-32bit~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI6-32bit-debuginfo", rpm:"libMagickCore-7_Q16HDRI6-32bit-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI6-32bit", rpm:"libMagickWand-7_Q16HDRI6-32bit~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI6-32bit-debuginfo", rpm:"libMagickWand-7_Q16HDRI6-32bit-debuginfo~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~7.0.7.34~10.21.1", rls:"openSUSELeap15.3"))) {
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