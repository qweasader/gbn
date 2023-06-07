# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.131296");
  script_cve_id("CVE-2016-4006", "CVE-2016-4076", "CVE-2016-4077", "CVE-2016-4078", "CVE-2016-4079", "CVE-2016-4080", "CVE-2016-4081", "CVE-2016-4082", "CVE-2016-4083", "CVE-2016-4084");
  script_tag(name:"creation_date", value:"2016-05-09 11:18:00 +0000 (Mon, 09 May 2016)");
  script_version("2022-06-27T10:12:27+0000");
  script_tag(name:"last_modification", value:"2022-06-27 10:12:27 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:27:00 +0000 (Sat, 03 Dec 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0153)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0153");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0153.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18260");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-19.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-20.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-21.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-22.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-23.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-24.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-25.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-26.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-27.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.3.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/news/20160422.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the MGASA-2016-0153 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated wireshark packages fix security vulnerabilities:

The NCP dissector could crash (CVE-2016-4076).

TShark could crash due to a packet reassembly bug (CVE-2016-4077).

The IEEE 802.11 dissector could crash (CVE-2016-4078).

The PKTC dissector could crash (CVE-2016-4079).

The PKTC dissector could crash (CVE-2016-4080).

The IAX2 dissector could go into an infinite loop (CVE-2016-4081).

Wireshark and TShark could exhaust the stack (CVE-2016-4006).

The GSM CBCH dissector could crash (CVE-2016-4082).

MS-WSP dissector crash (CVE-2016-4083, CVE-2016-4084).");

  script_tag(name:"affected", value:"'wireshark' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~2.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~2.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark6", rpm:"lib64wireshark6~2.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wiretap5", rpm:"lib64wiretap5~2.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wsutil6", rpm:"lib64wsutil6~2.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~2.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark6", rpm:"libwireshark6~2.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap5", rpm:"libwiretap5~2.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil6", rpm:"libwsutil6~2.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~2.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tshark", rpm:"tshark~2.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~2.0.3~1.mga5", rls:"MAGEIA5"))) {
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
