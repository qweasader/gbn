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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0698.1");
  script_cve_id("CVE-2022-25235", "CVE-2022-25236", "CVE-2022-25313", "CVE-2022-25314", "CVE-2022-25315");
  script_tag(name:"creation_date", value:"2022-03-04 04:07:05 +0000 (Fri, 04 Mar 2022)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-25 18:46:00 +0000 (Fri, 25 Feb 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0698-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0698-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220698-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat' package(s) announced via the SUSE-SU-2022:0698-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for expat fixes the following issues:

CVE-2022-25236: Fixed possible namespace-separator characters insertion
 into namespace URIs (bsc#1196025).

CVE-2022-25235: Fixed UTF-8 character validation in a certain context
 (bsc#1196026).

CVE-2022-25313: Fixed stack exhaustion in build_model() via uncontrolled
 recursion (bsc#1196168).

CVE-2022-25314: Fixed integer overflow in copyString (bsc#1196169).

CVE-2022-25315: Fixed integer overflow in storeRawNames (bsc#1196171).");

  script_tag(name:"affected", value:"'expat' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"expat", rpm:"expat~2.1.0~21.18.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"expat-debuginfo", rpm:"expat-debuginfo~2.1.0~21.18.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"expat-debuginfo-32bit", rpm:"expat-debuginfo-32bit~2.1.0~21.18.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"expat-debugsource", rpm:"expat-debugsource~2.1.0~21.18.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1", rpm:"libexpat1~2.1.0~21.18.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-32bit", rpm:"libexpat1-32bit~2.1.0~21.18.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-debuginfo", rpm:"libexpat1-debuginfo~2.1.0~21.18.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-debuginfo-32bit", rpm:"libexpat1-debuginfo-32bit~2.1.0~21.18.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"expat", rpm:"expat~2.1.0~21.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"expat-debuginfo", rpm:"expat-debuginfo~2.1.0~21.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"expat-debuginfo-32bit", rpm:"expat-debuginfo-32bit~2.1.0~21.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"expat-debugsource", rpm:"expat-debugsource~2.1.0~21.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1", rpm:"libexpat1~2.1.0~21.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-32bit", rpm:"libexpat1-32bit~2.1.0~21.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-debuginfo", rpm:"libexpat1-debuginfo~2.1.0~21.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-debuginfo-32bit", rpm:"libexpat1-debuginfo-32bit~2.1.0~21.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"expat", rpm:"expat~2.1.0~21.18.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"expat-debuginfo", rpm:"expat-debuginfo~2.1.0~21.18.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"expat-debuginfo-32bit", rpm:"expat-debuginfo-32bit~2.1.0~21.18.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"expat-debugsource", rpm:"expat-debugsource~2.1.0~21.18.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1", rpm:"libexpat1~2.1.0~21.18.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-32bit", rpm:"libexpat1-32bit~2.1.0~21.18.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-debuginfo", rpm:"libexpat1-debuginfo~2.1.0~21.18.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-debuginfo-32bit", rpm:"libexpat1-debuginfo-32bit~2.1.0~21.18.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"expat", rpm:"expat~2.1.0~21.18.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"expat-debuginfo", rpm:"expat-debuginfo~2.1.0~21.18.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"expat-debuginfo-32bit", rpm:"expat-debuginfo-32bit~2.1.0~21.18.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"expat-debugsource", rpm:"expat-debugsource~2.1.0~21.18.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1", rpm:"libexpat1~2.1.0~21.18.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-32bit", rpm:"libexpat1-32bit~2.1.0~21.18.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-debuginfo", rpm:"libexpat1-debuginfo~2.1.0~21.18.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-debuginfo-32bit", rpm:"libexpat1-debuginfo-32bit~2.1.0~21.18.1", rls:"SLES12.0SP5"))) {
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
