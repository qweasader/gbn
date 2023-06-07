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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0908.2");
  script_cve_id("CVE-2015-5276");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:07 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0908-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0908-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160908-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc5' package(s) announced via the SUSE-SU-2016:0908-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The GNU Compiler Collection was updated to version 5.3.1, which brings several fixes and enhancements.
The following security issue has been fixed:
- Fix C++11 std::random_device short read issue that could lead to
 predictable randomness. (CVE-2015-5276, bsc#945842)
The following non-security issues have been fixed:
- Enable frame pointer for TARGET_64BIT_MS_ABI when stack is misaligned.
 Fixes internal compiler error when building Wine. (bsc#966220)
- Fix a PowerPC specific issue in gcc-go that broke compilation of newer
 versions of Docker. (bsc#964468)
- Fix HTM built-ins on PowerPC. (bsc#955382)
- Fix libgo certificate lookup. (bsc#953831)
- Suppress deprecated-declarations warnings for inline definitions of
 deprecated virtual methods. (bsc#939460)
- Revert accidental libffi ABI breakage on aarch64. (bsc#968771)
- On x86_64, set default 32bit code generation to -march=x86-64 rather
 than -march=i586.
- Add experimental File System TS library.");

  script_tag(name:"affected", value:"'gcc5' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libatomic1-32bit", rpm:"libatomic1-32bit~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatomic1", rpm:"libatomic1~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffi4-32bit", rpm:"libffi4-32bit~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffi4", rpm:"libffi4~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1-32bit", rpm:"libgcc_s1-32bit~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc_s1", rpm:"libgcc_s1~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran3-32bit", rpm:"libgfortran3-32bit~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran3", rpm:"libgfortran3~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1-32bit", rpm:"libgomp1-32bit~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgomp1", rpm:"libgomp1~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0-32bit", rpm:"libquadmath0-32bit~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquadmath0", rpm:"libquadmath0~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-32bit", rpm:"libstdc++6-32bit~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-locale", rpm:"libstdc++6-locale~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
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
