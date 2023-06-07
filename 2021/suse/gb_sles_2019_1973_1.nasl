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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1973.1");
  script_cve_id("CVE-2019-11068", "CVE-2019-5419");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-03-27T10:19:43+0000");
  script_tag(name:"last_modification", value:"2023-03-27 10:19:43 +0000 (Mon, 27 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-24 18:27:00 +0000 (Fri, 24 Mar 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1973-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1973-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191973-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rmt-server' package(s) announced via the SUSE-SU-2019:1973-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rmt-server to version 2.3.1 fixes the following issues:
Fix mirroring logic when errors are encountered (bsc#1140492)

Refactor RMT::Mirror to download metadata/licenses in parallel

Check repo metadata GPG signatures during mirroring (bsc#1132690)

Add rmt-server-config subpackage with nginx configs (fate#327816,
 bsc#1136081)

Fix dependency to removed boot_cli_i18n file (bsc#1136020)

Add `rmt-cli systems list` command to list registered systems

Fix create UUID when system_uuid file empty (bsc#1138316)

Fix duplicate nginx location in rmt-server-pubcloud (bsc#1135222)

Mirror additional repos that were enabled during mirroring (bsc#1132690)

Make service IDs consistent across different RMT instances (bsc#1134428)

Make SMT data import scripts faster (bsc#1134190)

Fix incorrect triggering of registration sharing (bsc#1129392)

Fix license mirroring issue in some non-SUSE repositories (bsc#1128858)

Update dependencies to fix vulnerabilities in rails (CVE-2019-5419,
 bsc#1129271) and nokogiri (CVE-2019-11068, bsc#1132160)

Allow RMT registration to work under HTTP as well as HTTPS.

Offline migration from SLE 15 to SLE 15 SP1 will add Python2 module

Online migrations will automatically add additional modules to the
 client systems depending on the base product

Supply log severity to journald

Breaking Change: Added headers to generated CSV files");

  script_tag(name:"affected", value:"'rmt-server' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP1, SUSE Linux Enterprise Module for Server Applications 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"rmt-server-debuginfo", rpm:"rmt-server-debuginfo~2.3.1~3.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rmt-server-pubcloud", rpm:"rmt-server-pubcloud~2.3.1~3.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rmt-server", rpm:"rmt-server~2.3.1~3.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rmt-server-config", rpm:"rmt-server-config~2.3.1~3.3.3", rls:"SLES15.0SP1"))) {
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
