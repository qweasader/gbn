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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0068");
  script_cve_id("CVE-2021-4190");
  script_tag(name:"creation_date", value:"2022-02-18 03:17:16 +0000 (Fri, 18 Feb 2022)");
  script_version("2022-02-18T03:17:16+0000");
  script_tag(name:"last_modification", value:"2022-02-18 03:17:16 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-10 18:32:00 +0000 (Mon, 10 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0068)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0068");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0068.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30035");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2021-22");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2022-01");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2022-02");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2022-03");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2022-04");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2022-05");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-3.4.12.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/news/20220210.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the MGASA-2022-0068 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kafka dissector infinite loop (CVE-2021-4190).

RTMPT dissector infinite loop (wnpa-sec-2022-01).

Large loops in multiple dissectors (wnpa-sec-2022-02).

PVFS dissector crash (wnpa-sec-2022-03).

CSN.1 dissector crash (wnpa-sec-2022-04).

CMS dissector crash (wnpa-sec-2022-05).");

  script_tag(name:"affected", value:"'wireshark' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~3.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~3.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark14", rpm:"lib64wireshark14~3.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wiretap11", rpm:"lib64wiretap11~3.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wsutil12", rpm:"lib64wsutil12~3.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~3.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14", rpm:"libwireshark14~3.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11", rpm:"libwiretap11~3.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12", rpm:"libwsutil12~3.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~3.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tshark", rpm:"tshark~3.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~3.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~3.4.12~1.mga8", rls:"MAGEIA8"))) {
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
