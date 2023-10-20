# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0151");
  script_cve_id("CVE-2021-21898", "CVE-2021-21899", "CVE-2021-21900", "CVE-2021-45343");
  script_tag(name:"creation_date", value:"2022-04-25 04:24:37 +0000 (Mon, 25 Apr 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-23 19:19:00 +0000 (Tue, 23 Nov 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0151)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0151");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0151.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29720");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/RDI3HCTCACMIC7I4ILB3NRU6DCMADI5H/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2838");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/VUMH3CWGVSMR2UIZEA35Q5UB7PDVVVYS/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6TWLTKRSHNPCLQL7UXQSITHNYJT5XSK5/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libdxfrw' package(s) announced via the MGASA-2022-0151 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A code execution vulnerability exists in the dwgCompressor::decompress18()
functionality of LibreCad libdxfrw 2.2.0-rc2-19-ge02f3580. A specially-crafted
.dwg file can lead to an out-of-bounds write. An attacker can provide a
malicious file to trigger this vulnerability. (CVE-2021-21898)

A code execution vulnerability exists in the dwgCompressor::copyCompBytes21
functionality of LibreCad libdxfrw 2.2.0-rc2-19-ge02f3580. A specially-crafted
.dwg file can lead to a heap buffer overflow. An attacker can provide a
malicious file to trigger this vulnerability. (CVE-2021-21899)

A code execution vulnerability exists in the dxfRW::processLType()
functionality of LibreCad libdxfrw 2.2.0-rc2-19-ge02f3580. A specially-crafted
.dxf file can lead to a use-after-free vulnerability. An attacker can provide
a malicious file to trigger this vulnerability. (CVE-2021-21900)

In LibreCAD 2.2.0, a NULL pointer dereference in the HATCH handling of libdxfrw
allows an attacker to crash the application using a crafted DXF document.
(CVE-2021-45343)");

  script_tag(name:"affected", value:"'libdxfrw' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"dwg2dxf", rpm:"dwg2dxf~1.0.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dxfrw-devel", rpm:"lib64dxfrw-devel~1.0.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dxfrw1", rpm:"lib64dxfrw1~1.0.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw", rpm:"libdxfrw~1.0.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw-devel", rpm:"libdxfrw-devel~1.0.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdxfrw1", rpm:"libdxfrw1~1.0.1~1.1.mga8", rls:"MAGEIA8"))) {
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
