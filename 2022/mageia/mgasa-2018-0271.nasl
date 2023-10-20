# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0271");
  script_cve_id("CVE-2018-10119", "CVE-2018-10120", "CVE-2018-10583", "CVE-2018-6871");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0271)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0271");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0271.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22579");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2018-1055/");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2018-10119/");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2018-10120/");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2018-10583/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4111");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4178");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreoffice' package(s) announced via the MGASA-2018-0271 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

LibreOffice before 5.4.5 and 6.x before 6.0.1 allows remote attackers to read
arbitrary files via =WEBSERVICE calls in a document, which use the
COM.MICROSOFT.WEBSERVICE function. (CVE-2018-6871)

sot/source/sdstor/stgstrms.cxx in LibreOffice before 5.4.5.1 and 6.x before
6.0.1.1 uses an incorrect integer data type in the StgSmallStrm class, which
allows remote attackers to cause a denial of service (use-after-free with write
access) or possibly have unspecified other impact via a crafted document that
uses the structured storage ole2 wrapper file format. (CVE-2018-10119)

The SwCTBWrapper::Read function in sw/source/filter/ww8/ww8toolbar.cxx in
LibreOffice before 5.4.6.1 and 6.x before 6.0.2.1 does not validate a
customizations index, which allows remote attackers to cause a denial of service
(heap-based buffer overflow with write access) or possibly have unspecified
other impact via a crafted document that contains a certain Microsoft Word
record. (CVE-2018-10120)

An information disclosure vulnerability occurs when LibreOffice 6.0.3 and Apache
OpenOffice Writer 4.1.5 automatically process and initiate an SMB connection
embedded in a malicious file, as demonstrated by
xlink:href=file://192.168.0.2/test.jpg within an office:document-content element
in a .odt XML document. (CVE-2018-10583)");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"autocorr-af", rpm:"autocorr-af~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-bg", rpm:"autocorr-bg~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ca", rpm:"autocorr-ca~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-cs", rpm:"autocorr-cs~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-da", rpm:"autocorr-da~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-de", rpm:"autocorr-de~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-en", rpm:"autocorr-en~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-es", rpm:"autocorr-es~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-fa", rpm:"autocorr-fa~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-fi", rpm:"autocorr-fi~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-fr", rpm:"autocorr-fr~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ga", rpm:"autocorr-ga~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-hr", rpm:"autocorr-hr~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-hu", rpm:"autocorr-hu~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-is", rpm:"autocorr-is~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-it", rpm:"autocorr-it~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ja", rpm:"autocorr-ja~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ko", rpm:"autocorr-ko~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-lb", rpm:"autocorr-lb~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-lt", rpm:"autocorr-lt~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-mn", rpm:"autocorr-mn~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-nl", rpm:"autocorr-nl~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-pl", rpm:"autocorr-pl~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-pt", rpm:"autocorr-pt~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ro", rpm:"autocorr-ro~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ru", rpm:"autocorr-ru~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-sk", rpm:"autocorr-sk~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-sl", rpm:"autocorr-sl~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-sr", rpm:"autocorr-sr~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-sv", rpm:"autocorr-sv~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-tr", rpm:"autocorr-tr~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-vi", rpm:"autocorr-vi~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-zh", rpm:"autocorr-zh~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice", rpm:"libreoffice~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base", rpm:"libreoffice-base~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-bsh", rpm:"libreoffice-bsh~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-calc", rpm:"libreoffice-calc~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-core", rpm:"libreoffice-core~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-data", rpm:"libreoffice-data~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-draw", rpm:"libreoffice-draw~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-emailmerge", rpm:"libreoffice-emailmerge~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-filters", rpm:"libreoffice-filters~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gdb-debug-support", rpm:"libreoffice-gdb-debug-support~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-glade", rpm:"libreoffice-glade~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-graphicfilter", rpm:"libreoffice-graphicfilter~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gtk2", rpm:"libreoffice-gtk2~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gtk3", rpm:"libreoffice-gtk3~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-impress", rpm:"libreoffice-impress~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-kde4", rpm:"libreoffice-kde4~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-af", rpm:"libreoffice-langpack-af~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ar", rpm:"libreoffice-langpack-ar~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-as", rpm:"libreoffice-langpack-as~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-bg", rpm:"libreoffice-langpack-bg~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-bn", rpm:"libreoffice-langpack-bn~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-br", rpm:"libreoffice-langpack-br~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ca", rpm:"libreoffice-langpack-ca~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-cs", rpm:"libreoffice-langpack-cs~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-cy", rpm:"libreoffice-langpack-cy~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-da", rpm:"libreoffice-langpack-da~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-de", rpm:"libreoffice-langpack-de~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-dz", rpm:"libreoffice-langpack-dz~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-el", rpm:"libreoffice-langpack-el~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-en", rpm:"libreoffice-langpack-en~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-es", rpm:"libreoffice-langpack-es~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-et", rpm:"libreoffice-langpack-et~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-eu", rpm:"libreoffice-langpack-eu~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-fa", rpm:"libreoffice-langpack-fa~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-fi", rpm:"libreoffice-langpack-fi~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-fr", rpm:"libreoffice-langpack-fr~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ga", rpm:"libreoffice-langpack-ga~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-gl", rpm:"libreoffice-langpack-gl~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-gu", rpm:"libreoffice-langpack-gu~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-he", rpm:"libreoffice-langpack-he~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-hi", rpm:"libreoffice-langpack-hi~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-hr", rpm:"libreoffice-langpack-hr~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-hu", rpm:"libreoffice-langpack-hu~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-id", rpm:"libreoffice-langpack-id~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-it", rpm:"libreoffice-langpack-it~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ja", rpm:"libreoffice-langpack-ja~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-kk", rpm:"libreoffice-langpack-kk~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-kn", rpm:"libreoffice-langpack-kn~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ko", rpm:"libreoffice-langpack-ko~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-lt", rpm:"libreoffice-langpack-lt~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-lv", rpm:"libreoffice-langpack-lv~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-mai", rpm:"libreoffice-langpack-mai~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ml", rpm:"libreoffice-langpack-ml~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-mr", rpm:"libreoffice-langpack-mr~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-nb", rpm:"libreoffice-langpack-nb~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-nl", rpm:"libreoffice-langpack-nl~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-nn", rpm:"libreoffice-langpack-nn~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-nr", rpm:"libreoffice-langpack-nr~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-nso", rpm:"libreoffice-langpack-nso~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-or", rpm:"libreoffice-langpack-or~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-pa", rpm:"libreoffice-langpack-pa~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-pl", rpm:"libreoffice-langpack-pl~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-pt", rpm:"libreoffice-langpack-pt~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-pt_BR", rpm:"libreoffice-langpack-pt_BR~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ro", rpm:"libreoffice-langpack-ro~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ru", rpm:"libreoffice-langpack-ru~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-si", rpm:"libreoffice-langpack-si~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-sk", rpm:"libreoffice-langpack-sk~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-sl", rpm:"libreoffice-langpack-sl~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-sr", rpm:"libreoffice-langpack-sr~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ss", rpm:"libreoffice-langpack-ss~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-st", rpm:"libreoffice-langpack-st~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-sv", rpm:"libreoffice-langpack-sv~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ta", rpm:"libreoffice-langpack-ta~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-te", rpm:"libreoffice-langpack-te~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-th", rpm:"libreoffice-langpack-th~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-tn", rpm:"libreoffice-langpack-tn~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-tr", rpm:"libreoffice-langpack-tr~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ts", rpm:"libreoffice-langpack-ts~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-uk", rpm:"libreoffice-langpack-uk~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ve", rpm:"libreoffice-langpack-ve~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-xh", rpm:"libreoffice-langpack-xh~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-zh_CN", rpm:"libreoffice-langpack-zh_CN~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-zh_TW", rpm:"libreoffice-langpack-zh_TW~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-zu", rpm:"libreoffice-langpack-zu~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-librelogo", rpm:"libreoffice-librelogo~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-math", rpm:"libreoffice-math~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-nlpsolver", rpm:"libreoffice-nlpsolver~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-officebean", rpm:"libreoffice-officebean~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-officebean-common", rpm:"libreoffice-officebean-common~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-ogltrans", rpm:"libreoffice-ogltrans~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-opensymbol-fonts", rpm:"libreoffice-opensymbol-fonts~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-pdfimport", rpm:"libreoffice-pdfimport~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-postgresql", rpm:"libreoffice-postgresql~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-pyuno", rpm:"libreoffice-pyuno~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-rhino", rpm:"libreoffice-rhino~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-sdk", rpm:"libreoffice-sdk~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-sdk-doc", rpm:"libreoffice-sdk-doc~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-ure", rpm:"libreoffice-ure~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-ure-common", rpm:"libreoffice-ure-common~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-wiki-publisher", rpm:"libreoffice-wiki-publisher~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-writer", rpm:"libreoffice-writer~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-x11", rpm:"libreoffice-x11~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-xsltfilter", rpm:"libreoffice-xsltfilter~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreofficekit", rpm:"libreofficekit~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreofficekit-devel", rpm:"libreofficekit-devel~5.3.7.2~3.mga6", rls:"MAGEIA6"))) {
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
