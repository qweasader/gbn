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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1986.1");
  script_cve_id("CVE-2016-2399");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1986-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1986-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171986-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libquicktime' package(s) announced via the SUSE-SU-2017:1986-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libquicktime fixes the following issues:
Security issue fixed:
- CVE-2016-2399: Adjust patch to prevent endless loop when there are less
 than 256 bytes to read. (bsc#1022805)");

  script_tag(name:"affected", value:"'libquicktime' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-debugsource", rpm:"libquicktime-debugsource~1.2.4~14.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime0", rpm:"libquicktime0~1.2.4~14.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime0-debuginfo", rpm:"libquicktime0-debuginfo~1.2.4~14.3.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-debugsource", rpm:"libquicktime-debugsource~1.2.4~14.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime0", rpm:"libquicktime0~1.2.4~14.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime0-debuginfo", rpm:"libquicktime0-debuginfo~1.2.4~14.3.1", rls:"SLES12.0SP3"))) {
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
