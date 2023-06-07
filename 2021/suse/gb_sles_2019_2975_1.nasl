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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2975.1");
  script_cve_id("CVE-2019-12523", "CVE-2019-12525", "CVE-2019-12526", "CVE-2019-12527", "CVE-2019-12529", "CVE-2019-12854", "CVE-2019-13345", "CVE-2019-18676", "CVE-2019-18677", "CVE-2019-18678", "CVE-2019-18679", "CVE-2019-3688");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-11 00:15:00 +0000 (Sat, 11 Jul 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2975-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2975-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192975-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the SUSE-SU-2019:2975-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for squid to version 4.9 fixes the following issues:

Security issues fixed:
CVE-2019-13345: Fixed multiple cross-site scripting vulnerabilities in
 cachemgr.cgi (bsc#1140738).

CVE-2019-12526: Fixed potential remote code execution during URN
 processing (bsc#1156326).

CVE-2019-12523,CVE-2019-18676: Fixed multiple improper validations in
 URI processing (bsc#1156329).

CVE-2019-18677: Fixed Cross-Site Request Forgery in HTTP Request
 processing (bsc#1156328).

CVE-2019-18678: Fixed incorrect message parsing which could have led to
 HTTP request splitting issue (bsc#1156323).

CVE-2019-18679: Fixed information disclosure when processing HTTP Digest
 Authentication (bsc#1156324).

Other issues addressed:

 * Fixed DNS failures when peer name was configured with any upper case
 characters
 * Fixed several rock cache_dir corruption issues");

  script_tag(name:"affected", value:"'squid' package(s) on SUSE Linux Enterprise Module for Server Applications 15, SUSE Linux Enterprise Module for Server Applications 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.9~5.11.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~4.9~5.11.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-debugsource", rpm:"squid-debugsource~4.9~5.11.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.9~5.11.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~4.9~5.11.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-debugsource", rpm:"squid-debugsource~4.9~5.11.1", rls:"SLES15.0SP1"))) {
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
