# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0170");
  script_cve_id("CVE-2020-6819", "CVE-2020-6820", "CVE-2020-6821", "CVE-2020-6822", "CVE-2020-6825");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-01 16:07:00 +0000 (Fri, 01 May 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0170)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0170");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0170.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26455");
  script_xref(name:"URL", value:"https://www.thunderbird.net/en-US/thunderbird/68.7.0/releasenotes/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-14/");
  script_xref(name:"URL", value:"https://enigmail.net/index.php/en/download/changelog#enig2.1.6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird, thunderbird-l10n' package(s) announced via the MGASA-2020-0170 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

Use-after-free while running the nsDocShell destructor. (CVE-2020-6819)

Use-after-free when handling a ReadableStream. (CVE-2020-6820)

Uninitialized memory could be read when using the WebGL copyTexSubImage
method. (CVE-2020-6821)

Out of bounds write in GMPDecodeData when processing large images.
(CVE-2020-6822)

Memory safety bugs fixed in Thunderbird 68.7.0. (CVE-2020-6825)");

  script_tag(name:"affected", value:"'thunderbird, thunderbird-l10n' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ar", rpm:"thunderbird-ar~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ast", rpm:"thunderbird-ast~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-be", rpm:"thunderbird-be~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-bg", rpm:"thunderbird-bg~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-br", rpm:"thunderbird-br~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ca", rpm:"thunderbird-ca~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-cs", rpm:"thunderbird-cs~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-cy", rpm:"thunderbird-cy~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-da", rpm:"thunderbird-da~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-de", rpm:"thunderbird-de~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-el", rpm:"thunderbird-el~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-en_GB", rpm:"thunderbird-en_GB~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-en_US", rpm:"thunderbird-en_US~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-enigmail", rpm:"thunderbird-enigmail~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_AR", rpm:"thunderbird-es_AR~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_ES", rpm:"thunderbird-es_ES~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-et", rpm:"thunderbird-et~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-eu", rpm:"thunderbird-eu~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fi", rpm:"thunderbird-fi~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fr", rpm:"thunderbird-fr~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fy_NL", rpm:"thunderbird-fy_NL~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ga_IE", rpm:"thunderbird-ga_IE~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gd", rpm:"thunderbird-gd~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gl", rpm:"thunderbird-gl~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-he", rpm:"thunderbird-he~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hr", rpm:"thunderbird-hr~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hsb", rpm:"thunderbird-hsb~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hu", rpm:"thunderbird-hu~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hy_AM", rpm:"thunderbird-hy_AM~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-id", rpm:"thunderbird-id~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-is", rpm:"thunderbird-is~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-it", rpm:"thunderbird-it~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ja", rpm:"thunderbird-ja~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ko", rpm:"thunderbird-ko~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-l10n", rpm:"thunderbird-l10n~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-lt", rpm:"thunderbird-lt~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nb_NO", rpm:"thunderbird-nb_NO~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nl", rpm:"thunderbird-nl~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nn_NO", rpm:"thunderbird-nn_NO~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pl", rpm:"thunderbird-pl~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_BR", rpm:"thunderbird-pt_BR~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_PT", rpm:"thunderbird-pt_PT~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ro", rpm:"thunderbird-ro~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ru", rpm:"thunderbird-ru~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-si", rpm:"thunderbird-si~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sk", rpm:"thunderbird-sk~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sl", rpm:"thunderbird-sl~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sq", rpm:"thunderbird-sq~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sv_SE", rpm:"thunderbird-sv_SE~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-tr", rpm:"thunderbird-tr~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-uk", rpm:"thunderbird-uk~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-vi", rpm:"thunderbird-vi~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_CN", rpm:"thunderbird-zh_CN~68.7.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_TW", rpm:"thunderbird-zh_TW~68.7.0~1.mga7", rls:"MAGEIA7"))) {
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
