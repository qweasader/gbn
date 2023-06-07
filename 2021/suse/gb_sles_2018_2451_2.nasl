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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2451.2");
  script_cve_id("CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1124", "CVE-2018-1125", "CVE-2018-1126");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-30 13:15:00 +0000 (Tue, 30 Jul 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2451-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2451-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182451-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'procps' package(s) announced via the SUSE-SU-2018:2451-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for procps fixes the following security issues:
CVE-2018-1122: Prevent local privilege escalation in top. If a user ran
 top with HOME unset in an attacker-controlled directory, the attacker
 could have achieved privilege escalation by exploiting one of several
 vulnerabilities in the config_file() function (bsc#1092100).

CVE-2018-1123: Prevent denial of service in ps via mmap buffer overflow.
 Inbuilt protection in ps maped a guard page at the end of the overflowed
 buffer, ensuring that the impact of this flaw is limited to a crash
 (temporary denial of service) (bsc#1092100).

CVE-2018-1124: Prevent multiple integer overflows leading to a heap
 corruption in file2strvec function. This allowed a privilege escalation
 for a local attacker who can create entries in procfs by starting
 processes, which could result in crashes or arbitrary code execution in
 proc utilities run by
 other users (bsc#1092100).

CVE-2018-1125: Prevent stack buffer overflow in pgrep. This
 vulnerability was mitigated by FORTIFY limiting the impact to a crash
 (bsc#1092100).

CVE-2018-1126: Ensure correct integer size in proc/alloc.* to prevent
 truncation/integer overflow issues (bsc#1092100).");

  script_tag(name:"affected", value:"'procps' package(s) on SUSE CaaS Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libprocps3", rpm:"libprocps3~3.3.9~11.14.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocps3-debuginfo", rpm:"libprocps3-debuginfo~3.3.9~11.14.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps", rpm:"procps~3.3.9~11.14.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debuginfo", rpm:"procps-debuginfo~3.3.9~11.14.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debugsource", rpm:"procps-debugsource~3.3.9~11.14.1", rls:"SLES12.0SP3"))) {
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
