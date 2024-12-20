# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0243");
  script_cve_id("CVE-2017-2834", "CVE-2017-2835", "CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-25 15:20:55 +0000 (Fri, 25 May 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0243)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0243");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0243.html");
  script_xref(name:"URL", value:"http://blog.talosintelligence.com/2017/07/vulnerbility-spotlight-freerdp-multiple.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21427");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/JNO6AUPEMWZQNGI7PEVPRUZD3OFNCQ4R/");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0336");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0337");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0338");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0339");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0340");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0341");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp, remmina, vinagre' package(s) announced via the MGASA-2017-0243 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An exploitable code execution vulnerability exists in the authentication
functionality of FreeRDP 2.0.0-beta1+android11. A specially crafted server
response can cause an out-of-bounds write resulting in an exploitable
condition. An attacker can compromise the server or use a man in the middle
attack to trigger this vulnerability (CVE-2017-2834).

An exploitable code execution vulnerability exists in the RDP receive
functionality of FreeRDP 2.0.0-beta1+android11. A specially crafted server
response can cause an out-of-bounds write resulting in an exploitable
condition. An attacker can compromise the server or use a man in the middle to
trigger this vulnerability (CVE-2017-2835).

An exploitable denial of service vulnerability exists within the reading of
proprietary server certificates in FreeRDP 2.0.0-beta1+android11. A specially
crafted challenge packet can cause the program termination leading to a denial
of service condition. An attacker can compromise the server or use man in the
middle to trigger this vulnerability (CVE-2017-2836).

An exploitable denial of service vulnerability exists within the handling of
security data in FreeRDP 2.0.0-beta1+android11. A specially crafted challenge
packet can cause the program termination leading to a denial of service
condition. An attacker can compromise the server or use man in the middle to
trigger this vulnerability (CVE-2017-2837).

An exploitable denial of service vulnerability exists within the handling of
challenge packets in FreeRDP 2.0.0-beta1+android11. A specially crafted
challenge packet can cause the program termination leading to a denial of
service condition. An attacker can compromise the server or use man in the
middle to trigger this vulnerability (CVE-2017-2838, CVE-2017-2839).");

  script_tag(name:"affected", value:"'freerdp, remmina, vinagre' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.0.0~0.rc0.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp-devel", rpm:"lib64freerdp-devel~2.0.0~0.rc0.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp2", rpm:"lib64freerdp2~2.0.0~0.rc0.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp-devel", rpm:"libfreerdp-devel~2.0.0~0.rc0.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.0.0~0.rc0.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina", rpm:"remmina~1.2.0~0.rcgit.19.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-devel", rpm:"remmina-devel~1.2.0~0.rcgit.19.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-common", rpm:"remmina-plugins-common~1.2.0~0.rcgit.19.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-gnome", rpm:"remmina-plugins-gnome~1.2.0~0.rcgit.19.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-nx", rpm:"remmina-plugins-nx~1.2.0~0.rcgit.19.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-rdp", rpm:"remmina-plugins-rdp~1.2.0~0.rcgit.19.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-spice", rpm:"remmina-plugins-spice~1.2.0~0.rcgit.19.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-telepathy", rpm:"remmina-plugins-telepathy~1.2.0~0.rcgit.19.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-vnc", rpm:"remmina-plugins-vnc~1.2.0~0.rcgit.19.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"remmina-plugins-xdmcp", rpm:"remmina-plugins-xdmcp~1.2.0~0.rcgit.19.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vinagre", rpm:"vinagre~3.22.0~3.1.mga6", rls:"MAGEIA6"))) {
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
