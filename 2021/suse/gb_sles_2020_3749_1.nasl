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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3749.1");
  script_cve_id("CVE-2020-13844");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-18 21:15:00 +0000 (Sun, 18 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3749-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3749-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203749-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc7' package(s) announced via the SUSE-SU-2020:3749-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gcc7 fixes the following issues:

CVE-2020-13844: Added mitigation for aarch64 Straight Line Speculation
 issue (bsc#1172798)

Enable fortran for the nvptx offload compiler.

Update README.First-for.SuSE.packagers

avoid assembler errors with AVX512 gather and scatter instructions when
 using -masm=intel.

Backport the aarch64 -moutline-atomics feature and accumulated fixes but
 not its default enabling. [jsc#SLE-12209, bsc#1167939]

Fixed 32bit libgnat.so link. [bsc#1178675]

Fixed memcpy miscompilation on aarch64. [bsc#1178624, bsc#1178577]

Fixed debug line info for try/catch. [bsc#1178614]

Remove -mbranch-protection=standard (aarch64 flag) when gcc7 is used to
 build gcc7 (ie when ada is enabled)

Fixed corruption of pass private ->aux via DF. [gcc#94148]

Fixed debug information issue with inlined functions and passed by
 reference arguments. [gcc#93888]

Fixed binutils release date detection issue.

Fixed register allocation issue with exception handling code on s390x.
 [bsc#1161913]

Fixed miscompilation of some atomic code on aarch64. [bsc#1150164]");

  script_tag(name:"affected", value:"'gcc7' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP3, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"cpp7", rpm:"cpp7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp7-debuginfo", rpm:"cpp7-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7", rpm:"gcc7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++", rpm:"gcc7-c++~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++-debuginfo", rpm:"gcc7-c++-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debuginfo", rpm:"gcc7-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debugsource", rpm:"gcc7-debugsource~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran", rpm:"gcc7-fortran~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran-debuginfo", rpm:"gcc7-fortran-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4", rpm:"libasan4~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-debuginfo", rpm:"libasan4-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5", rpm:"libcilkrts5~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-debuginfo", rpm:"libcilkrts5-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-32bit", rpm:"libgfortran4-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-32bit-debuginfo", rpm:"libgfortran4-32bit-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4", rpm:"libgfortran4~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-debuginfo", rpm:"libgfortran4-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc7", rpm:"libstdc++6-devel-gcc7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0", rpm:"libubsan0~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-debuginfo", rpm:"libubsan0-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc7", rpm:"cross-nvptx-gcc7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-newlib7-devel", rpm:"cross-nvptx-newlib7-devel~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-32bit", rpm:"gcc7-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-ada", rpm:"gcc7-ada~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-ada-debuginfo", rpm:"gcc7-ada-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++-32bit", rpm:"gcc7-c++-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran-32bit", rpm:"gcc7-fortran-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-info", rpm:"gcc7-info~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-locale", rpm:"gcc7-locale~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-objc", rpm:"gcc7-objc~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-objc-debuginfo", rpm:"gcc7-objc-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada7", rpm:"libada7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada7-debuginfo", rpm:"libada7-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-32bit", rpm:"libasan4-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-32bit-debuginfo", rpm:"libasan4-32bit-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-32bit", rpm:"libcilkrts5-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-32bit-debuginfo", rpm:"libcilkrts5-32bit-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc7-32bit", rpm:"libstdc++6-devel-gcc7-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-32bit", rpm:"libubsan0-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-32bit-debuginfo", rpm:"libubsan0-32bit-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"cpp7", rpm:"cpp7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp7-debuginfo", rpm:"cpp7-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7", rpm:"gcc7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++", rpm:"gcc7-c++~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++-debuginfo", rpm:"gcc7-c++-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debuginfo", rpm:"gcc7-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debugsource", rpm:"gcc7-debugsource~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran", rpm:"gcc7-fortran~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran-debuginfo", rpm:"gcc7-fortran-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4", rpm:"libasan4~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-debuginfo", rpm:"libasan4-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5", rpm:"libcilkrts5~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-debuginfo", rpm:"libcilkrts5-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-32bit", rpm:"libgfortran4-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-32bit-debuginfo", rpm:"libgfortran4-32bit-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4", rpm:"libgfortran4~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-debuginfo", rpm:"libgfortran4-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc7", rpm:"libstdc++6-devel-gcc7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0", rpm:"libubsan0~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-debuginfo", rpm:"libubsan0-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc7", rpm:"cross-nvptx-gcc7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-newlib7-devel", rpm:"cross-nvptx-newlib7-devel~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-32bit", rpm:"gcc7-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-ada", rpm:"gcc7-ada~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-ada-debuginfo", rpm:"gcc7-ada-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++-32bit", rpm:"gcc7-c++-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran-32bit", rpm:"gcc7-fortran-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-info", rpm:"gcc7-info~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-locale", rpm:"gcc7-locale~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-objc", rpm:"gcc7-objc~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-objc-debuginfo", rpm:"gcc7-objc-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada7", rpm:"libada7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada7-debuginfo", rpm:"libada7-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-32bit", rpm:"libasan4-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-32bit-debuginfo", rpm:"libasan4-32bit-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-32bit", rpm:"libcilkrts5-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-32bit-debuginfo", rpm:"libcilkrts5-32bit-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc7-32bit", rpm:"libstdc++6-devel-gcc7-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-32bit", rpm:"libubsan0-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-32bit-debuginfo", rpm:"libubsan0-32bit-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"cpp7", rpm:"cpp7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp7-debuginfo", rpm:"cpp7-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7", rpm:"gcc7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++", rpm:"gcc7-c++~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++-debuginfo", rpm:"gcc7-c++-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debuginfo", rpm:"gcc7-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debugsource", rpm:"gcc7-debugsource~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran", rpm:"gcc7-fortran~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran-debuginfo", rpm:"gcc7-fortran-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4", rpm:"libasan4~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-debuginfo", rpm:"libasan4-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5", rpm:"libcilkrts5~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-debuginfo", rpm:"libcilkrts5-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-32bit", rpm:"libgfortran4-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-32bit-debuginfo", rpm:"libgfortran4-32bit-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4", rpm:"libgfortran4~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-debuginfo", rpm:"libgfortran4-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc7", rpm:"libstdc++6-devel-gcc7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0", rpm:"libubsan0~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-debuginfo", rpm:"libubsan0-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-gcc7", rpm:"cross-nvptx-gcc7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-nvptx-newlib7-devel", rpm:"cross-nvptx-newlib7-devel~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-32bit", rpm:"gcc7-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-ada", rpm:"gcc7-ada~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-ada-debuginfo", rpm:"gcc7-ada-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++-32bit", rpm:"gcc7-c++-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran-32bit", rpm:"gcc7-fortran-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-info", rpm:"gcc7-info~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-locale", rpm:"gcc7-locale~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-objc", rpm:"gcc7-objc~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-objc-debuginfo", rpm:"gcc7-objc-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada7", rpm:"libada7~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada7-debuginfo", rpm:"libada7-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-32bit", rpm:"libasan4-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-32bit-debuginfo", rpm:"libasan4-32bit-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-32bit", rpm:"libcilkrts5-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcilkrts5-32bit-debuginfo", rpm:"libcilkrts5-32bit-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc7-32bit", rpm:"libstdc++6-devel-gcc7-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-32bit", rpm:"libubsan0-32bit~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-32bit-debuginfo", rpm:"libubsan0-32bit-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"cpp7", rpm:"cpp7~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp7-debuginfo", rpm:"cpp7-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7", rpm:"gcc7~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-ada", rpm:"gcc7-ada~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-ada-debuginfo", rpm:"gcc7-ada-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++", rpm:"gcc7-c++~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-c++-debuginfo", rpm:"gcc7-c++-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debuginfo", rpm:"gcc7-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-debugsource", rpm:"gcc7-debugsource~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran", rpm:"gcc7-fortran~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-fortran-debuginfo", rpm:"gcc7-fortran-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-info", rpm:"gcc7-info~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-locale", rpm:"gcc7-locale~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-objc", rpm:"gcc7-objc~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc7-objc-debuginfo", rpm:"gcc7-objc-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada7", rpm:"libada7~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libada7-debuginfo", rpm:"libada7-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4", rpm:"libasan4~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan4-debuginfo", rpm:"libasan4-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4", rpm:"libgfortran4~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran4-debuginfo", rpm:"libgfortran4-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++6-devel-gcc7", rpm:"libstdc++6-devel-gcc7~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0", rpm:"libubsan0~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubsan0-debuginfo", rpm:"libubsan0-debuginfo~7.5.0+r278197~4.19.2", rls:"SLES15.0"))) {
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
