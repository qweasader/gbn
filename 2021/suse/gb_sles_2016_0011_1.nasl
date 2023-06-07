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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0011.1");
  script_cve_id("CVE-2014-9732", "CVE-2015-4467", "CVE-2015-4468", "CVE-2015-4469", "CVE-2015-4470", "CVE-2015-4471", "CVE-2015-4472");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0011-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0011-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160011-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmspack' package(s) announced via the SUSE-SU-2016:0011-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libmspack was updated to fix security issues.
These security issues were fixed:
* CVE-2014-9732: The cabd_extract function in cabd.c in libmspack did not
 properly maintain decompression callbacks in certain cases where an
 invalid file follows a valid file, which allowed remote attackers to
 cause a denial of service (NULL pointer dereference and application
 crash) via a crafted CAB archive (bnc#934524).
* CVE-2015-4467: The chmd_init_decomp function in chmd.c in libmspack did
 not properly validate the reset interval, which allowed remote attackers
 to cause a denial of service (divide-by-zero error and application
 crash) via a crafted CHM file (bnc#934525).
* CVE-2015-4468: Multiple integer overflows in the search_chunk function
 in chmd.c in libmspack allowed remote attackers to cause a denial of
 service (buffer over-read and application crash) via a crafted CHM file
 (bnc#934526).
* CVE-2015-4469: The chmd_read_headers function in chmd.c in libmspack did
 not validate name lengths, which allowed remote attackers to cause a
 denial of service (buffer over-read and application crash) via a crafted
 CHM file (bnc#934526).
* CVE-2015-4470: Off-by-one error in the inflate function in mszipd.c in
 libmspack allowed remote attackers to cause a denial of service (buffer
 over-read and application crash) via a crafted CAB archive (bnc#934527).
* CVE-2015-4471: Off-by-one error in the lzxd_decompress function in
 lzxd.c in libmspack allowed remote attackers to cause a denial of
 service (buffer under-read and application crash) via a crafted CAB
 archive (bnc#934528).
* CVE-2015-4472: Off-by-one error in the READ_ENCINT macro in chmd.c in
 libmspack allowed remote attackers to cause a denial of service
 (application crash) or possibly have unspecified other impact via a
 crafted CHM file (bnc#934529).");

  script_tag(name:"affected", value:"'libmspack' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Software Development Kit 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libmspack-debugsource", rpm:"libmspack-debugsource~0.4~14.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmspack0", rpm:"libmspack0~0.4~14.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmspack0-debuginfo", rpm:"libmspack0-debuginfo~0.4~14.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libmspack-debugsource", rpm:"libmspack-debugsource~0.4~14.4", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmspack0", rpm:"libmspack0~0.4~14.4", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmspack0-debuginfo", rpm:"libmspack0-debuginfo~0.4~14.4", rls:"SLES12.0SP1"))) {
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
