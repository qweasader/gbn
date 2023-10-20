# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0168");
  script_cve_id("CVE-2013-2486", "CVE-2013-2487", "CVE-2013-3555", "CVE-2013-3557", "CVE-2013-3558", "CVE-2013-3559", "CVE-2013-3560", "CVE-2013-3561", "CVE-2013-3562");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Mageia: Security Advisory (MGASA-2013-0168)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0168");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0168.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-23.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-24.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-25.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-26.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-27.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-28.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-29.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-30.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-31.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.7.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/news/20130517.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2013/05/20/7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the MGASA-2013-0168 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The RELOAD dissector could go into an infinite loop (CVE-2013-2486,
CVE-2013-2487).

The GTPv2 dissector could crash (CVE-2013-3555).

The ASN.1 BER dissector could crash (CVE-2013-3557).

The PPP CCP dissector could crash (CVE-2013-3558).

The DCP ETSI dissector could crash (CVE-2013-3559).

The MPEG DSM-CC dissector could crash (CVE-2013-3560).

The Websocket dissector could crash. The MySQL dissector could go into an
infinite loop. The ETCH dissector could go into a large loop (CVE-2013-3561,
CVE-2013-3562).");

  script_tag(name:"affected", value:"'wireshark' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~1.8.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~1.8.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark2", rpm:"lib64wireshark2~1.8.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~1.8.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark2", rpm:"libwireshark2~1.8.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~1.8.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tshark", rpm:"tshark~1.8.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~1.8.7~1.mga3", rls:"MAGEIA3"))) {
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
