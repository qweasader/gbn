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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2934.1");
  script_cve_id("CVE-2018-14598", "CVE-2018-14599", "CVE-2018-14600");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:36 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2934-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2934-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182934-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-libX11' package(s) announced via the SUSE-SU-2018:2934-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xorg-x11-libX11 fixes the following issues:
CVE-2018-14599: The function XListExtensions was vulnerable to an
 off-by-one error caused by malicious server responses, leading to DoS or
 possibly unspecified other impact (bsc#1102062)

CVE-2018-14600: The function XListExtensions interpreted a variable as
 signed instead of unsigned, resulting in an out-of-bounds write (of up
 to 128 bytes), leading to DoS or remote code execution (bsc#1102068)

CVE-2018-14598: A malicious server could have sent a reply in which the
 first string overflows, causing a variable to be set to NULL that will
 be freed later
 on, leading to DoS (segmentation fault) (bsc#1102073)");

  script_tag(name:"affected", value:"'xorg-x11-libX11' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libX11-32bit", rpm:"xorg-x11-libX11-32bit~7.4~5.11.72.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libX11", rpm:"xorg-x11-libX11~7.4~5.11.72.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libX11-32bit", rpm:"xorg-x11-libX11-32bit~7.4~5.11.72.9.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libX11", rpm:"xorg-x11-libX11~7.4~5.11.72.9.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libX11-x86", rpm:"xorg-x11-libX11-x86~7.4~5.11.72.9.1", rls:"SLES11.0SP4"))) {
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
