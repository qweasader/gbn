# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0076");
  script_cve_id("CVE-2017-6014");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-17 17:22:13 +0000 (Fri, 17 Feb 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0076)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0076");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0076.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20392");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.11.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/news/20170303.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-03.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-04.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-05.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-06.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-07.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-08.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-09.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-10.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-11.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the MGASA-2017-0076 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The wireshark package has been updated to version 2.0.11, which fixes two
security issues where a malformed packet trace could cause it to crash or
go into an infinite loop, and fixes several other bugs as well. See the
release notes for details.");

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

  if(!isnull(res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~2.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~2.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark7", rpm:"lib64wireshark7~2.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wiretap5", rpm:"lib64wiretap5~2.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wsutil6", rpm:"lib64wsutil6~2.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~2.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark7", rpm:"libwireshark7~2.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap5", rpm:"libwiretap5~2.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil6", rpm:"libwsutil6~2.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~2.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tshark", rpm:"tshark~2.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~2.0.11~1.mga5", rls:"MAGEIA5"))) {
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
