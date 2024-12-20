# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0295");
  script_cve_id("CVE-2022-23803", "CVE-2022-23804", "CVE-2022-23946", "CVE-2022-23947");
  script_tag(name:"creation_date", value:"2022-08-26 04:58:48 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-11 03:12:28 +0000 (Fri, 11 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0295)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0295");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0295.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30109");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/5EMCGSSP3FIWCSL2KXVXLF35JYZKZE5Q/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2998");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5214");
  script_xref(name:"URL", value:"https://www.kicad.org/blog/2022/07/KiCad-6.0.7-Release/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kicad' package(s) announced via the MGASA-2022-0295 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple buffer overflows were discovered in Kicad, a suite of programs
for the creation of printed circuit boards, which could result in the
execution of arbitrary code if malformed Gerber/Excellon files, as
follows.

A stack-based buffer overflow vulnerability exists in the Gerber Viewer
gerber and excellon ReadXYCoord coordinate parsing functionality of KiCad
EDA 6.0.1 and master commit de006fc010. A specially-crafted gerber or
excellon file can lead to code execution. An attacker can provide a
malicious file to trigger this vulnerability. (CVE-2022-23803)

A stack-based buffer overflow vulnerability exists in the Gerber Viewer
gerber and excellon ReadIJCoord coordinate parsing functionality of KiCad
EDA 6.0.1 and master commit de006fc010. A specially-crafted gerber or
excellon file can lead to code execution. An attacker can provide a
malicious file to trigger this vulnerability. (CVE-2022-23804)

A stack-based buffer overflow vulnerability exists in the Gerber Viewer
gerber and excellon GCodeNumber parsing functionality of KiCad EDA 6.0.1
and master commit de006fc010. A specially-crafted gerber or excellon file
can lead to code execution. An attacker can provide a malicious file to
trigger this vulnerability. (CVE-2022-23946)

A stack-based buffer overflow vulnerability exists in the Gerber Viewer
gerber and excellon DCodeNumber parsing functionality of KiCad EDA 6.0.1
and master commit de006fc010. A specially-crafted gerber or excellon file
can lead to code execution. An attacker can provide a malicious file to
trigger this vulnerability. (CVE-2022-23947)");

  script_tag(name:"affected", value:"'kicad' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"kicad", rpm:"kicad~5.1.12~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kicad-doc", rpm:"kicad-doc~5.1.12~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kicad-i18n", rpm:"kicad-i18n~5.1.12~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kicad-library", rpm:"kicad-library~5.1.12~1.1.mga8", rls:"MAGEIA8"))) {
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
