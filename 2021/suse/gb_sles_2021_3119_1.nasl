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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3119.1");
  script_cve_id("CVE-2021-3677");
  script_tag(name:"creation_date", value:"2021-09-23 07:04:43 +0000 (Thu, 23 Sep 2021)");
  script_version("2022-03-12T04:13:29+0000");
  script_tag(name:"last_modification", value:"2022-03-12 04:13:29 +0000 (Sat, 12 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 20:58:00 +0000 (Thu, 10 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3119-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3119-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213119-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql12' package(s) announced via the SUSE-SU-2021:3119-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql12 fixes the following issues:

CVE-2021-3677: Fixed memory disclosure in certain queries (bsc#1189748).

Fixed build with llvm12 on s390x (bsc#1185952).

Re-enabled icu for PostgreSQL 10 (bsc#1179945).

Made the dependency of postgresqlXX-server-devel on llvm and clang
 optional (bsc#1187751).

llvm12 breaks PostgreSQL 11 and 12 on s390x. Use llvm11 as a workaround
 (bsc#1185952).");

  script_tag(name:"affected", value:"'postgresql12' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql12", rpm:"postgresql12~12.8~3.18.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-contrib", rpm:"postgresql12-contrib~12.8~3.18.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-contrib-debuginfo", rpm:"postgresql12-contrib-debuginfo~12.8~3.18.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-debuginfo", rpm:"postgresql12-debuginfo~12.8~3.18.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-debugsource", rpm:"postgresql12-debugsource~12.8~3.18.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-docs", rpm:"postgresql12-docs~12.8~3.18.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plperl", rpm:"postgresql12-plperl~12.8~3.18.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plperl-debuginfo", rpm:"postgresql12-plperl-debuginfo~12.8~3.18.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plpython", rpm:"postgresql12-plpython~12.8~3.18.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-plpython-debuginfo", rpm:"postgresql12-plpython-debuginfo~12.8~3.18.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-pltcl", rpm:"postgresql12-pltcl~12.8~3.18.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-pltcl-debuginfo", rpm:"postgresql12-pltcl-debuginfo~12.8~3.18.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-server", rpm:"postgresql12-server~12.8~3.18.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql12-server-debuginfo", rpm:"postgresql12-server-debuginfo~12.8~3.18.2", rls:"SLES12.0SP5"))) {
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
