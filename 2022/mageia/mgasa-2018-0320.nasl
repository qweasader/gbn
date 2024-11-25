# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0320");
  script_cve_id("CVE-2018-14339", "CVE-2018-14340", "CVE-2018-14341", "CVE-2018-14342", "CVE-2018-14343", "CVE-2018-14344", "CVE-2018-14368", "CVE-2018-14369", "CVE-2018-7325");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-12 18:02:06 +0000 (Wed, 12 Sep 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0320)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0320");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0320.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23330");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.16.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/news/20180718.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-06.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-34.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-35.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-36.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-37.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-38.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-39.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-40.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-41.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the MGASA-2018-0320 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"RPKI-Router infinite loop (CVE-2018-7325).

MMSE dissector infinite loop (CVE-2018-14339).

Multiple dissectors could crash (CVE-2018-14340).

DICOM dissector crash (CVE-2018-14341).

BGP dissector large loop (CVE-2018-14342).

ASN.1 BER dissector crash (CVE-2018-14343).

ISMP dissector crash (CVE-2018-14344).

Bazaar dissector infinite loop (CVE-2018-14368).

HTTP2 dissector crash (CVE-2018-14369).");

  script_tag(name:"affected", value:"'wireshark' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark8", rpm:"lib64wireshark8~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wiretap6", rpm:"lib64wiretap6~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wscodecs1", rpm:"lib64wscodecs1~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wsutil7", rpm:"lib64wsutil7~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark8", rpm:"libwireshark8~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap6", rpm:"libwiretap6~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil7", rpm:"libwsutil7~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tshark", rpm:"tshark~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.2.16~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~2.2.16~1.mga6", rls:"MAGEIA6"))) {
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
