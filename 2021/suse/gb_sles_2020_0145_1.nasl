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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0145.1");
  script_cve_id("CVE-2019-5068");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-01 13:15:00 +0000 (Mon, 01 Jun 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0145-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0145-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200145-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mesa' package(s) announced via the SUSE-SU-2020:0145-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Mesa fixes the following issues:

Security issue fixed:
CVE-2019-5068: Fixed exploitable shared memory permissions vulnerability
 (bsc#1156015).");

  script_tag(name:"affected", value:"'Mesa' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Workstation Extension 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"Mesa", rpm:"Mesa~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-32bit", rpm:"Mesa-32bit~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-debugsource", rpm:"Mesa-debugsource~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri", rpm:"Mesa-dri~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-32bit", rpm:"Mesa-dri-32bit~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-debuginfo", rpm:"Mesa-dri-debuginfo~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-debuginfo-32bit", rpm:"Mesa-dri-debuginfo-32bit~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-drivers-debugsource", rpm:"Mesa-drivers-debugsource~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1", rpm:"Mesa-libEGL1~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1-32bit", rpm:"Mesa-libEGL1-32bit~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1-debuginfo", rpm:"Mesa-libEGL1-debuginfo~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1-debuginfo-32bit", rpm:"Mesa-libEGL1-debuginfo-32bit~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1", rpm:"Mesa-libGL1~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1-32bit", rpm:"Mesa-libGL1-32bit~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1-debuginfo", rpm:"Mesa-libGL1-debuginfo~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1-debuginfo-32bit", rpm:"Mesa-libGL1-debuginfo-32bit~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv2-2", rpm:"Mesa-libGLESv2-2~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv2-2-debuginfo", rpm:"Mesa-libGLESv2-2-debuginfo~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0", rpm:"Mesa-libglapi0~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0-32bit", rpm:"Mesa-libglapi0-32bit~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0-debuginfo", rpm:"Mesa-libglapi0-debuginfo~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0-debuginfo-32bit", rpm:"Mesa-libglapi0-debuginfo-32bit~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1", rpm:"libgbm1~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-32bit", rpm:"libgbm1-32bit~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-debuginfo", rpm:"libgbm1-debuginfo~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-debuginfo-32bit", rpm:"libgbm1-debuginfo-32bit~18.0.2~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxatracker2", rpm:"libxatracker2~1.0.0~8.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxatracker2-debuginfo", rpm:"libxatracker2-debuginfo~1.0.0~8.3.2", rls:"SLES12.0SP4"))) {
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
