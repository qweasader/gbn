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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3651.1");
  script_cve_id("CVE-2020-25668", "CVE-2020-25705", "CVE-2020-8694");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-02 12:15:00 +0000 (Fri, 02 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3651-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3651-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203651-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 32 for SLE 12 SP3)' package(s) announced via the SUSE-SU-2020:3651-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.180-94_121 fixes several issues.

The following security issues were fixed:

CVE-2020-25668: Fixed a concurrency use-after-free in con_font_op
 (bsc#1178622).

CVE-2020-8694: Fixed an insufficient access control in the Linux kernel
 driver for some Intel(R) Processors which might have allowed an
 authenticated user to potentially enable information disclosure via
 local access (bsc#1178700).

CVE-2020-25705: Fixed a flaw which could have allowed an off-path remote
 user to effectively bypass source port UDP randomization (bsc#1178783).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 32 for SLE 12 SP3)' package(s) on SUSE Linux Enterprise Module for Live Patching 15, SUSE Linux Enterprise Module for Live Patching 15-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_129-default", rpm:"kgraft-patch-4_4_121-92_129-default~7~2.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_135-default", rpm:"kgraft-patch-4_4_121-92_135-default~5~2.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_138-default", rpm:"kgraft-patch-4_4_121-92_138-default~5~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_141-default", rpm:"kgraft-patch-4_4_121-92_141-default~4~2.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_113-default", rpm:"kgraft-patch-4_4_180-94_113-default~9~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_113-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_113-default-debuginfo~9~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_116-default", rpm:"kgraft-patch-4_4_180-94_116-default~6~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_116-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_116-default-debuginfo~6~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_121-default", rpm:"kgraft-patch-4_4_180-94_121-default~5~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_121-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_121-default-debuginfo~5~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_124-default", rpm:"kgraft-patch-4_4_180-94_124-default~5~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_124-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_124-default-debuginfo~5~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_127-default", rpm:"kgraft-patch-4_4_180-94_127-default~5~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_127-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_127-default-debuginfo~5~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_130-default", rpm:"kgraft-patch-4_4_180-94_130-default~4~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_130-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_130-default-debuginfo~4~2.1", rls:"SLES12.0SP3"))) {
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
