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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1993.1");
  script_cve_id("CVE-2018-0495");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:43 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1993-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1993-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181993-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgcrypt' package(s) announced via the SUSE-SU-2018:1993-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libgcrypt fixes the following issue:
The following security issue was fixed:
- CVE-2018-0495: Fixed a novel side-channel attack, by enabling blinding
 for ECDSA signatures (bsc#1097410)");

  script_tag(name:"affected", value:"'libgcrypt' package(s) on SUSE Linux Enterprise Module for Basesystem 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-debugsource", rpm:"libgcrypt-debugsource~1.8.2~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-devel", rpm:"libgcrypt-devel~1.8.2~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-devel-debuginfo", rpm:"libgcrypt-devel-debuginfo~1.8.2~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20", rpm:"libgcrypt20~1.8.2~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-32bit", rpm:"libgcrypt20-32bit~1.8.2~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-32bit-debuginfo", rpm:"libgcrypt20-32bit-debuginfo~1.8.2~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-debuginfo", rpm:"libgcrypt20-debuginfo~1.8.2~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-hmac", rpm:"libgcrypt20-hmac~1.8.2~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-hmac-32bit", rpm:"libgcrypt20-hmac-32bit~1.8.2~6.3.1", rls:"SLES15.0"))) {
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
