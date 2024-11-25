# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0047");
  script_cve_id("CVE-2018-14404", "CVE-2018-14567", "CVE-2018-9251");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-18 16:59:15 +0000 (Tue, 18 Sep 2018)");

  script_name("Mageia: Security Advisory (MGASA-2019-0047)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0047");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0047.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23410");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/G5AFZARX7BUSU24J2MJ4AHX5OE47UXQA/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3739-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2, perl-XML-LibXML' package(s) announced via the MGASA-2019-0047 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in libxml2 2.9.8. The xz_decomp function in xzlib.c, if
--with-lzma is used, allows remote attackers to cause a denial of service
(infinite loop) via a crafted XML file that triggers LZMA_MEMLIMIT_ERROR,
as demonstrated by xmllint (CVE-2018-9251, CVE-2018-14567).

A null pointer dereference vulnerability exists in the
xpath.c:xmlXPathCompOpEval() function of libxml2 when parsing invalid
XPath expression. Applications processing untrusted XSL format inputs
with the use of libxml2 library may be vulnerable to denial of service
attack due to crash of the application (CVE-2018-14404).

The libxml2 package has been updated to version 2.9.9 to fix these
issues and other bugs.

The perl-XML-LibXML package has been rebuilt against the updated libxml2.");

  script_tag(name:"affected", value:"'libxml2, perl-XML-LibXML' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64xml2-devel", rpm:"lib64xml2-devel~2.9.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xml2_2", rpm:"lib64xml2_2~2.9.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.9.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.9.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python3", rpm:"libxml2-python3~2.9.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-utils", rpm:"libxml2-utils~2.9.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2_2", rpm:"libxml2_2~2.9.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-XML-LibXML", rpm:"perl-XML-LibXML~2.13.200~1.1.mga6", rls:"MAGEIA6"))) {
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
