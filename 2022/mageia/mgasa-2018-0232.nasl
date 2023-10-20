# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0232");
  script_cve_id("CVE-2018-9918");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0232)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0232");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0232.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22961");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/I4ZEBKAKN5LJYYF7ZALERVHHMBSTN2ET/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qpdf' package(s) announced via the MGASA-2018-0232 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in QPDF through 8.0.2. libqpdf.a mishandles certain
'expected dictionary key but found non-name object' cases, allowing
remote attackers to cause a denial of service (stack exhaustion),
related to the QPDFObjectHandle and QPDF_Dictionary classes
(CVE-2018-9918).");

  script_tag(name:"affected", value:"'qpdf' package(s) on Mageia 5, Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64qpdf-devel", rpm:"lib64qpdf-devel~7.1.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qpdf18", rpm:"lib64qpdf18~7.1.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqpdf-devel", rpm:"libqpdf-devel~7.1.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqpdf18", rpm:"libqpdf18~7.1.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpdf", rpm:"qpdf~7.1.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpdf-doc", rpm:"qpdf-doc~7.1.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64qpdf-devel", rpm:"lib64qpdf-devel~7.1.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qpdf18", rpm:"lib64qpdf18~7.1.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqpdf-devel", rpm:"libqpdf-devel~7.1.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqpdf18", rpm:"libqpdf18~7.1.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpdf", rpm:"qpdf~7.1.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpdf-doc", rpm:"qpdf-doc~7.1.1~1.1.mga6", rls:"MAGEIA6"))) {
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
