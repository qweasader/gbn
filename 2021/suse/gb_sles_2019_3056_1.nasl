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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3056.1");
  script_cve_id("CVE-2018-10811", "CVE-2018-16151", "CVE-2018-16152", "CVE-2018-17540", "CVE-2018-5388");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-01 01:15:00 +0000 (Sun, 01 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3056-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3056-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193056-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'strongswan' package(s) announced via the SUSE-SU-2019:3056-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for strongswan fixes the following issues:

Security issues fixed:
CVE-2018-5388: Fixed a buffer underflow which may allow to a remote
 attacker with local user credentials to resource exhaustion and denial
 of service while reading from the socket (bsc#1094462).

CVE-2018-10811: Fixed a denial of service during the IKEv2 key
 derivation if the openssl plugin is used in FIPS mode and HMAC-MD5 is
 negotiated as PRF (bsc#1093536).

CVE-2018-16151,CVE-2018-16152: Fixed multiple flaws in the gmp plugin
 which might lead to authorization bypass (bsc#1107874).

CVE-2018-17540: Fixed an improper input validation in gmp plugin
 (bsc#1109845).");

  script_tag(name:"affected", value:"'strongswan' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Module for Packagehub Subpackages 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~5.6.0~4.3.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debuginfo", rpm:"strongswan-debuginfo~5.6.0~4.3.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debugsource", rpm:"strongswan-debugsource~5.6.0~4.3.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-doc", rpm:"strongswan-doc~5.6.0~4.3.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-hmac", rpm:"strongswan-hmac~5.6.0~4.3.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec", rpm:"strongswan-ipsec~5.6.0~4.3.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec-debuginfo", rpm:"strongswan-ipsec-debuginfo~5.6.0~4.3.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0", rpm:"strongswan-libs0~5.6.0~4.3.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0-debuginfo", rpm:"strongswan-libs0-debuginfo~5.6.0~4.3.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-nm", rpm:"strongswan-nm~5.6.0~4.3.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-nm-debuginfo", rpm:"strongswan-nm-debuginfo~5.6.0~4.3.2", rls:"SLES15.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~5.6.0~4.3.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debuginfo", rpm:"strongswan-debuginfo~5.6.0~4.3.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debugsource", rpm:"strongswan-debugsource~5.6.0~4.3.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-doc", rpm:"strongswan-doc~5.6.0~4.3.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-hmac", rpm:"strongswan-hmac~5.6.0~4.3.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec", rpm:"strongswan-ipsec~5.6.0~4.3.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec-debuginfo", rpm:"strongswan-ipsec-debuginfo~5.6.0~4.3.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0", rpm:"strongswan-libs0~5.6.0~4.3.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0-debuginfo", rpm:"strongswan-libs0-debuginfo~5.6.0~4.3.2", rls:"SLES15.0SP1"))) {
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