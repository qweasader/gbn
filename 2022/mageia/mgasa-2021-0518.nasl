# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0518");
  script_cve_id("CVE-2021-39920", "CVE-2021-39921", "CVE-2021-39922", "CVE-2021-39924", "CVE-2021-39925", "CVE-2021-39926", "CVE-2021-39928", "CVE-2021-39929");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-24 14:31:57 +0000 (Wed, 24 Nov 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0518)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0518");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0518.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29670");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-3.4.10.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-3.4.8.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-3.4.9.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/news/20210825.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/news/20211006.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/news/20211117.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2021-07");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2021-08");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2021-09");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2021-10");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2021-11");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2021-12");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2021-13");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2021-14");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2021-15");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the MGASA-2021-0518 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IPPUSB dissector crash (CVE-2021-39920).
Modbus dissector crash (CVE-2021-39921).
C12.22 dissector crash (CVE-2021-39922).
PNRP dissector large loop (wnpa-sec-2021-11).
Bluetooth DHT dissector large loop (CVE-2021-39924).
Bluetooth SDP dissector crash (CVE-2021-39925).
Bluetooth HCI_ISO dissector crash (CVE-2021-39926).
IEEE 802.11 dissector crash (CVE-2021-39928).
Bluetooth DHT dissector crash (CVE-2021-39929).");

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

  if(!isnull(res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~3.4.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~3.4.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark14", rpm:"lib64wireshark14~3.4.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wiretap11", rpm:"lib64wiretap11~3.4.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wsutil12", rpm:"lib64wsutil12~3.4.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~3.4.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14", rpm:"libwireshark14~3.4.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11", rpm:"libwiretap11~3.4.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12", rpm:"libwsutil12~3.4.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~3.4.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tshark", rpm:"tshark~3.4.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~3.4.10~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~3.4.10~1.mga8", rls:"MAGEIA8"))) {
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
