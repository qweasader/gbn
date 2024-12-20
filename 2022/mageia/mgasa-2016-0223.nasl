# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0223");
  script_cve_id("CVE-2016-5350", "CVE-2016-5351", "CVE-2016-5352", "CVE-2016-5353", "CVE-2016-5354", "CVE-2016-5355", "CVE-2016-5356", "CVE-2016-5357", "CVE-2016-5358", "CVE-2016-5359");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-09 18:54:18 +0000 (Tue, 09 Aug 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0223)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0223");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0223.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18663");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.4.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/news/20160607.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-29.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-30.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-31.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-32.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-33.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-34.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-35.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-36.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-37.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-38.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the MGASA-2016-0223 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated wireshark packages fix security vulnerabilities:

The SPOOLS dissector could go into an infinite loop (CVE-2016-5350).

The IEEE 802.11 dissector could crash (CVE-2016-5351).

The IEEE 802.11 dissector could crash (CVE-2016-5352).

The UMTS FP dissector could crash (CVE-2016-5353).

Some USB dissectors could crash (CVE-2016-5354).

The Toshiba file parser could crash (CVE-2016-5355).

The CoSine file parser could crash (CVE-2016-5356).

The NetScreen file parser could crash (CVE-2016-5357).

The Ethernet dissector could crash (CVE-2016-5358).

Infinite loop in parse_wbxml_tag_defined() in WBXML Dissector
(CVE-2016-5359).");

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

  if(!isnull(res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~2.0.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~2.0.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark6", rpm:"lib64wireshark6~2.0.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wiretap5", rpm:"lib64wiretap5~2.0.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wsutil6", rpm:"lib64wsutil6~2.0.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~2.0.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark6", rpm:"libwireshark6~2.0.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap5", rpm:"libwiretap5~2.0.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil6", rpm:"libwsutil6~2.0.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~2.0.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tshark", rpm:"tshark~2.0.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.0.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~2.0.4~1.mga5", rls:"MAGEIA5"))) {
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
