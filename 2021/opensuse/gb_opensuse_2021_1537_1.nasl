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
  script_oid("1.3.6.1.4.1.25623.1.0.854358");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2021-3933", "CVE-2021-3941");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 12:55:00 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"creation_date", value:"2021-12-07 02:03:19 +0000 (Tue, 07 Dec 2021)");
  script_name("openSUSE: Security Advisory for openexr (openSUSE-SU-2021:1537-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1537-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EKJUN3YRRGAS46NITMDUWNKKE4DUYDHB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr'
  package(s) announced via the openSUSE-SU-2021:1537-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openexr fixes the following issues:

  - CVE-2021-3941: Fixed divide-by-zero in Imf_3_1:RGBtoXYZ (bsc#1192556).

  - CVE-2021-3933: Fixed integer-overflow in Imf_3_1:bytesPerDeepLineTable
       (bsc#1192498).

     This update was imported from the SUSE:SLE-15:Update update project.");

  script_tag(name:"affected", value:"'openexr' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23", rpm:"libIlmImf-2_2-23~2.2.1~lp152.7.23.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23-debuginfo", rpm:"libIlmImf-2_2-23-debuginfo~2.2.1~lp152.7.23.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23", rpm:"libIlmImfUtil-2_2-23~2.2.1~lp152.7.23.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23-debuginfo", rpm:"libIlmImfUtil-2_2-23-debuginfo~2.2.1~lp152.7.23.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr", rpm:"openexr~2.2.1~lp152.7.23.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-debuginfo", rpm:"openexr-debuginfo~2.2.1~lp152.7.23.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-debugsource", rpm:"openexr-debugsource~2.2.1~lp152.7.23.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-devel", rpm:"openexr-devel~2.2.1~lp152.7.23.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-doc", rpm:"openexr-doc~2.2.1~lp152.7.23.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23-32bit", rpm:"libIlmImf-2_2-23-32bit~2.2.1~lp152.7.23.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23-32bit-debuginfo", rpm:"libIlmImf-2_2-23-32bit-debuginfo~2.2.1~lp152.7.23.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23-32bit", rpm:"libIlmImfUtil-2_2-23-32bit~2.2.1~lp152.7.23.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23-32bit-debuginfo", rpm:"libIlmImfUtil-2_2-23-32bit-debuginfo~2.2.1~lp152.7.23.1", rls:"openSUSELeap15.2"))) {
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