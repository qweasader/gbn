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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14603.1");
  script_cve_id("CVE-2019-14834", "CVE-2020-25681", "CVE-2020-25682", "CVE-2020-25683", "CVE-2020-25684", "CVE-2020-25685", "CVE-2020-25686", "CVE-2020-25687");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:45 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-26 18:23:00 +0000 (Fri, 26 Mar 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14603-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14603-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114603-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq' package(s) announced via the SUSE-SU-2021:14603-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dnsmasq fixes the following issues:

CVE-2019-14834: Fixed a memory leak which could have allowed to remote
 attackers to cause denial of service via DHCP response creation
 (bsc#1154849)

bsc#1177077: Fixed DNSpooq vulnerabilities

CVE-2020-25684, CVE-2020-25685, CVE-2020-25686: Fixed multiple Cache
 poisoning attacks.

CVE-2020-25681, CVE-2020-25682, CVE-2020-25683, CVE-2020-25687: Fixed
 multiple potential Heap-based overflows when DNSSEC is enabled.

Retry query to other servers on receipt of SERVFAIL rcode (bsc#1176076)");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.78~0.17.15.1", rls:"SLES11.0SP4"))) {
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
