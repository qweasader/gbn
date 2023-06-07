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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0239");
  script_cve_id("CVE-2013-4242");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-05-12T12:25:31+0000");
  script_tag(name:"last_modification", value:"2022-05-12 12:25:31 +0000 (Thu, 12 May 2022)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2013-0239)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0239");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0239.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10850");
  script_xref(name:"URL", value:"http://lists.gnupg.org/pipermail/gnupg-announce/2013q3/000329.html");
  script_xref(name:"URL", value:"http://lists.gnupg.org/pipermail/gnupg-announce/2013q3/000330.html");
  script_xref(name:"URL", value:"http://eprint.iacr.org/2013/448");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2730");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2731");
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/advisory/MDVSA-2013:205/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg, libgcrypt' package(s) announced via the MGASA-2013-0239 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yarom and Falkner discovered that RSA secret keys in applications
using GnuPG 1.x, and using the libgcrypt library, could be leaked via a
side channel attack, where a malicious local user could obtain private
key information from another user on the system (CVE-2013-4242).");

  script_tag(name:"affected", value:"'gnupg, libgcrypt' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"gnupg", rpm:"gnupg~1.4.12~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gcrypt-devel", rpm:"lib64gcrypt-devel~1.5.0~2.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gcrypt11", rpm:"lib64gcrypt11~1.5.0~2.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt", rpm:"libgcrypt~1.5.0~2.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-devel", rpm:"libgcrypt-devel~1.5.0~2.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt11", rpm:"libgcrypt11~1.5.0~2.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"gnupg", rpm:"gnupg~1.4.14~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gcrypt-devel", rpm:"lib64gcrypt-devel~1.5.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gcrypt11", rpm:"lib64gcrypt11~1.5.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt", rpm:"libgcrypt~1.5.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-devel", rpm:"libgcrypt-devel~1.5.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt11", rpm:"libgcrypt11~1.5.3~1.mga3", rls:"MAGEIA3"))) {
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
