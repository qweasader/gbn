# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0129");
  script_cve_id("CVE-2018-18506", "CVE-2019-9788", "CVE-2019-9790", "CVE-2019-9791", "CVE-2019-9792", "CVE-2019-9793", "CVE-2019-9794", "CVE-2019-9795", "CVE-2019-9796", "CVE-2019-9801", "CVE-2019-9810", "CVE-2019-9813");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-29 19:35:56 +0000 (Mon, 29 Apr 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0129)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0129");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0129.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24541");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2LKJX4XFUISMUN6H4VQJY7MSG5SM7LGB/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-11/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-12/");
  script_xref(name:"URL", value:"https://www.thunderbird.net/en-US/thunderbird/60.6.0/releasenotes/");
  script_xref(name:"URL", value:"https://www.thunderbird.net/en-US/thunderbird/60.6.1/releasenotes/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird, thunderbird-l10n' package(s) announced via the MGASA-2019-0129 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use-after-free when removing in-use DOM elements. (CVE-2019-9790)

Type inference is incorrect for constructors entered through on-stack
replacement with IonMonkey. (CVE-2019-9791)

IonMonkey leaks JS_OPTIMIZED_OUT magic value to script. (CVE-2019-9792)

Improper bounds checks when Spectre mitigations are disabled.
(CVE-2019-9793)

Command line arguments not discarded during execution. (CVE-2019-9794)

Type-confusion in IonMonkey JIT compiler. (CVE-2019-9795)

Use-after-free with SMIL animation controller. (CVE-2019-9796)

Windows programs that are not 'URL Handlers' are exposed to web content.
(CVE-2019-9801)

Proxy Auto-Configuration file can define localhost access to be proxied.
(CVE-2018-18506)

Memory safety bugs fixed in Firefox 66, Firefox ESR 60.6, and Thunderbird
60.6. (CVE-2019-9788)

IonMonkey MArraySlice has incorrect alias information. (CVE-2019-9810)

Ionmonkey type confusion with __proto__ mutations. (CVE-2019-9813)");

  script_tag(name:"affected", value:"'thunderbird, thunderbird-l10n' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ar", rpm:"thunderbird-ar~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ast", rpm:"thunderbird-ast~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-be", rpm:"thunderbird-be~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-bg", rpm:"thunderbird-bg~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-br", rpm:"thunderbird-br~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ca", rpm:"thunderbird-ca~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-cs", rpm:"thunderbird-cs~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-cy", rpm:"thunderbird-cy~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-da", rpm:"thunderbird-da~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-de", rpm:"thunderbird-de~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-el", rpm:"thunderbird-el~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-en_GB", rpm:"thunderbird-en_GB~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-en_US", rpm:"thunderbird-en_US~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-enigmail", rpm:"thunderbird-enigmail~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_AR", rpm:"thunderbird-es_AR~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_ES", rpm:"thunderbird-es_ES~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-et", rpm:"thunderbird-et~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-eu", rpm:"thunderbird-eu~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fi", rpm:"thunderbird-fi~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fr", rpm:"thunderbird-fr~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fy_NL", rpm:"thunderbird-fy_NL~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ga_IE", rpm:"thunderbird-ga_IE~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gd", rpm:"thunderbird-gd~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gl", rpm:"thunderbird-gl~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-he", rpm:"thunderbird-he~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hr", rpm:"thunderbird-hr~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hsb", rpm:"thunderbird-hsb~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hu", rpm:"thunderbird-hu~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hy_AM", rpm:"thunderbird-hy_AM~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-id", rpm:"thunderbird-id~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-is", rpm:"thunderbird-is~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-it", rpm:"thunderbird-it~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ja", rpm:"thunderbird-ja~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ko", rpm:"thunderbird-ko~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-l10n", rpm:"thunderbird-l10n~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-lt", rpm:"thunderbird-lt~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nb_NO", rpm:"thunderbird-nb_NO~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nl", rpm:"thunderbird-nl~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nn_NO", rpm:"thunderbird-nn_NO~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pl", rpm:"thunderbird-pl~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_BR", rpm:"thunderbird-pt_BR~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_PT", rpm:"thunderbird-pt_PT~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ro", rpm:"thunderbird-ro~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ru", rpm:"thunderbird-ru~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-si", rpm:"thunderbird-si~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sk", rpm:"thunderbird-sk~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sl", rpm:"thunderbird-sl~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sq", rpm:"thunderbird-sq~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sv_SE", rpm:"thunderbird-sv_SE~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-tr", rpm:"thunderbird-tr~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-uk", rpm:"thunderbird-uk~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-vi", rpm:"thunderbird-vi~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_CN", rpm:"thunderbird-zh_CN~60.6.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_TW", rpm:"thunderbird-zh_TW~60.6.1~1.mga6", rls:"MAGEIA6"))) {
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
