# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.131118");
  script_cve_id("CVE-2015-7762", "CVE-2015-7763");
  script_tag(name:"creation_date", value:"2015-11-08 11:02:13 +0000 (Sun, 08 Nov 2015)");
  script_version("2022-06-27T10:12:26+0000");
  script_tag(name:"last_modification", value:"2022-06-27 10:12:26 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0424)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0424");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0424.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17050");
  script_xref(name:"URL", value:"http://openafs.org/pages/security/OPENAFS-SA-2015-007.txt");
  script_xref(name:"URL", value:"http://openafs.org/dl/openafs/1.6.14/RELNOTES-1.6.14");
  script_xref(name:"URL", value:"http://openafs.org/dl/openafs/1.6.14.1/RELNOTES-1.6.14.1");
  script_xref(name:"URL", value:"http://openafs.org/dl/openafs/1.6.15/RELNOTES-1.6.15");
  script_xref(name:"URL", value:"https://lists.openafs.org/pipermail/openafs-announce/2015/000493.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openafs' package(s) announced via the MGASA-2015-0424 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated openafs packages fix security vulnerabilities:

When constructing an Rx acknowledgment (ACK) packet, Andrew-derived Rx
implementations do not initialize three octets of data that are padding
in the C language structure and were inadvertently included in the wire
protocol (CVE-2015-7762).

Additionally, OpenAFS Rx before version 1.6.14 includes a variable-length
padding at the end of the ACK packet, in an attempt to detect the path MTU,
but only four octets of the additional padding are initialized
(CVE-2015-7763).");

  script_tag(name:"affected", value:"'openafs' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-libafs", rpm:"dkms-libafs~1.6.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs-devel", rpm:"lib64openafs-devel~1.6.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs-static-devel", rpm:"lib64openafs-static-devel~1.6.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs1", rpm:"lib64openafs1~1.6.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs-devel", rpm:"libopenafs-devel~1.6.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs-static-devel", rpm:"libopenafs-static-devel~1.6.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs1", rpm:"libopenafs1~1.6.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs", rpm:"openafs~1.6.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-client", rpm:"openafs-client~1.6.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-doc", rpm:"openafs-doc~1.6.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-server", rpm:"openafs-server~1.6.15~1.mga5", rls:"MAGEIA5"))) {
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
