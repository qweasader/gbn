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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0831.1");
  script_cve_id("CVE-2018-1000877", "CVE-2018-1000878", "CVE-2018-1000879", "CVE-2018-1000880", "CVE-2019-1000019", "CVE-2019-1000020");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:28 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-06 01:15:00 +0000 (Wed, 06 Nov 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0831-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0831-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190831-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the SUSE-SU-2019:0831-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libarchive fixes the following issues:

Security issues fixed:
CVE-2018-1000877: Fixed a double free vulnerability in RAR decoder
 (bsc#1120653)

CVE-2018-1000878: Fixed a Use-After-Free vulnerability in RAR decoder
 (bsc#1120654)

CVE-2018-1000879: Fixed a NULL Pointer Dereference vulnerability in ACL
 parser (bsc#1120656)

CVE-2018-1000880: Fixed an Improper Input Validation vulnerability in
 WARC parser (bsc#1120659)

CVE-2019-1000019: Fixed an Out-Of-Bounds Read vulnerability in 7zip
 decompression (bsc#1124341)

CVE-2019-1000020: Fixed an Infinite Loop vulnerability in ISO9660 parser
 (bsc#1124342)");

  script_tag(name:"affected", value:"'libarchive' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Development Tools 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"libarchive-debugsource", rpm:"libarchive-debugsource~3.3.2~3.8.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~3.3.2~3.8.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13", rpm:"libarchive13~3.3.2~3.8.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13-debuginfo", rpm:"libarchive13-debuginfo~3.3.2~3.8.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdtar", rpm:"bsdtar~3.3.2~3.8.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdtar-debuginfo", rpm:"bsdtar-debuginfo~3.3.2~3.8.4", rls:"SLES15.0"))) {
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
