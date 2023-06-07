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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0425");
  script_cve_id("CVE-2021-3826", "CVE-2022-38533");
  script_tag(name:"creation_date", value:"2022-11-14 04:25:42 +0000 (Mon, 14 Nov 2022)");
  script_version("2022-11-14T10:12:51+0000");
  script_tag(name:"last_modification", value:"2022-11-14 10:12:51 +0000 (Mon, 14 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 19:44:00 +0000 (Wed, 07 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0425)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0425");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0425.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31092");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/6AKZ2DTS3ATVN5PANNVLKLE5OP4OF25Q/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4MYLS3VR4OPL5ECRWOR4ZHMGXUSCJFZY/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils, gdb' package(s) announced via the MGASA-2022-0425 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libiberty: Heap/stack buffer overflow in the dlang_lname function in
d-demangle.c (CVE-2021-3826)
binutils: heap-based buffer overflow in bfd_getl32() when called by
strip_main() in objcopy.c via a crafted file (CVE-2022-38533)");

  script_tag(name:"affected", value:"'binutils, gdb' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.36.1~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb", rpm:"gdb~10.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-doc", rpm:"gdb-doc~10.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-gdbserver", rpm:"gdb-gdbserver~10.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-headless", rpm:"gdb-headless~10.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64binutils-devel", rpm:"lib64binutils-devel~2.36.1~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbinutils-devel", rpm:"libbinutils-devel~2.36.1~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"urpmi-debuginfo-install", rpm:"urpmi-debuginfo-install~10.1~5.1.mga8", rls:"MAGEIA8"))) {
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
