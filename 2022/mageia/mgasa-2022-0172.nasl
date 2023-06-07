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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0172");
  script_cve_id("CVE-2022-0856");
  script_tag(name:"creation_date", value:"2022-05-19 07:28:20 +0000 (Thu, 19 May 2022)");
  script_version("2022-05-19T07:28:20+0000");
  script_tag(name:"last_modification", value:"2022-05-19 07:28:20 +0000 (Thu, 19 May 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-15 18:10:00 +0000 (Tue, 15 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0172)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0172");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0172.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30364");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PUXQNAUH2W6TRXYZGBDFHQTMXINVMOJB/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcaca' package(s) announced via the MGASA-2022-0172 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libcaca is affected by a Divide By Zero issue via img2txt, which allows a
remote malicious user to cause a Denial of Service. (CVE-2022-0856)");

  script_tag(name:"affected", value:"'libcaca' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"caca-utils", rpm:"caca-utils~0.99~0.beta19.5.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64caca-devel", rpm:"lib64caca-devel~0.99~0.beta19.5.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64caca0", rpm:"lib64caca0~0.99~0.beta19.5.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca", rpm:"libcaca~0.99~0.beta19.5.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-devel", rpm:"libcaca-devel~0.99~0.beta19.5.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0", rpm:"libcaca0~0.99~0.beta19.5.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-caca", rpm:"python3-caca~0.99~0.beta19.5.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-caca", rpm:"ruby-caca~0.99~0.beta19.5.3.mga8", rls:"MAGEIA8"))) {
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
