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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0140");
  script_cve_id("CVE-2020-8696", "CVE-2020-8698");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-05-12T12:25:31+0000");
  script_tag(name:"last_modification", value:"2022-05-12 12:25:31 +0000 (Thu, 12 May 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-11 13:15:00 +0000 (Tue, 11 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0140)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0140");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0140.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28579");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00381.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2021-0140 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update adds new microcode updates to mitigate CVE-2020-8696 for Intel
Skylake server (50654) and Cascade Lake Server (50656 & 50657) processors.
The new microcode update mitigates an issue when using an active JTAG agent
like In Target Probe (ITP), Direct Connect Interface (DCI) or a Baseboard
Management Controller (BMC) to take the CPU JTAG/TAP out of reset and then
returning it to reset.

Improper isolation of shared resources in some Intel(R) Processors may
allow an authenticated user to potentially enable information disclosure
via local access (CVE-2020-8698).

Improper removal of sensitive information before storage or transfer in
some Intel(R) Processors may allow an authenticated user to potentially
enable information disclosure via local access (CVE-2020-8696).");

  script_tag(name:"affected", value:"'microcode' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20210216~1.mga7.nonfree", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20210216~1.mga8.nonfree", rls:"MAGEIA8"))) {
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
