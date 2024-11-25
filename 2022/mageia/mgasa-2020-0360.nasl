# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0360");
  script_cve_id("CVE-2020-12861", "CVE-2020-12862", "CVE-2020-12863", "CVE-2020-12864", "CVE-2020-12865", "CVE-2020-12866", "CVE-2020-12867");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-08 16:36:49 +0000 (Wed, 08 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0360)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0360");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0360.html");
  script_xref(name:"URL", value:"https://alioth-lists.debian.net/pipermail/sane-announce/2020/000041.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26712");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4470-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2231");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2332");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sane' package(s) announced via the MGASA-2020-0360 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap buffer overflow in SANE Backends before 1.0.30 allows a malicious
device connected to the same local network as the victim to execute arbitrary
code, aka GHSL-2020-080. (CVE-2020-12861)

An out-of-bounds read in SANE Backends before 1.0.30 may allow a malicious
device connected to the same local network as the victim to read important
information, such as the ASLR offsets of the program, aka GHSL-2020-082.
(CVE-2020-12862)

An out-of-bounds read in SANE Backends before 1.0.30 may allow a malicious
device connected to the same local network as the victim to read important
information, such as the ASLR offsets of the program, aka GHSL-2020-083.
(CVE-2020-12863)

An out-of-bounds read in SANE Backends before 1.0.30 may allow a malicious
device connected to the same local network as the victim to read important
information, such as the ASLR offsets of the program, aka GHSL-2020-081.
(CVE-2020-12864)

A heap buffer overflow in SANE Backends before 1.0.30 may allow a malicious
device connected to the same local network as the victim to execute arbitrary
code, aka GHSL-2020-084. (CVE-2020-12865)

A NULL pointer dereference in SANE Backends before 1.0.30 allows a malicious
device connected to the same local network as the victim to cause a denial of
service, GHSL-2020-079. (CVE-2020-12866)

A NULL pointer dereference in sanei_epson_net_read in SANE Backends before
1.0.30 allows a malicious device connected to the same local network as the
victim to cause a denial of service, aka GHSL-2020-075. (CVE-2020-12867)");

  script_tag(name:"affected", value:"'sane' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64sane1", rpm:"lib64sane1~1.0.28~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sane1-devel", rpm:"lib64sane1-devel~1.0.28~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsane1", rpm:"libsane1~1.0.28~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsane1-devel", rpm:"libsane1-devel~1.0.28~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sane", rpm:"sane~1.0.28~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sane-backends", rpm:"sane-backends~1.0.28~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sane-backends-doc", rpm:"sane-backends-doc~1.0.28~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sane-backends-iscan", rpm:"sane-backends-iscan~1.0.28~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"saned", rpm:"saned~1.0.28~1.1.mga7", rls:"MAGEIA7"))) {
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
