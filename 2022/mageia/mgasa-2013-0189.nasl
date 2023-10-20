# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0189");
  script_cve_id("CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1697");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2013-0189)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0189");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0189.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-49.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-50.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-51.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-53.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-54.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-55.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-56.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-59.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/known-vulnerabilities/firefoxESR.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2013-0981.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/known-vulnerabilities/thunderbirdESR.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2013-0982.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10621");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, firefox-l10n, thunderbird, thunderbird-l10n' package(s) announced via the MGASA-2013-0189 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated firefox packages fix security vulnerabilities..

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox (CVE-2013-1682, CVE-2013-1684, CVE-2013-1685, CVE-2013-1686,
CVE-2013-1687, CVE-2013-1690).

It was found that Firefox allowed data to be sent in the body of
XMLHttpRequest (XHR) HEAD requests. In some cases this could allow
attackers to conduct Cross-Site Request Forgery (CSRF) attacks
(CVE-2013-1692).

Timing differences in the way Firefox processed SVG image files could
allow an attacker to read data across domains, potentially leading to
information disclosure (CVE-2013-1693).

Two flaws were found in the way Firefox implemented some of its internal
structures (called wrappers). An attacker could use these flaws to bypass
some restrictions placed on them. This could lead to unexpected behavior or
a potentially exploitable crash (CVE-2013-1694, CVE-2013-1697).


Updated thunderbird packages fix security vulnerabilities..

Several flaws were found in the processing of malformed content. Malicious
content could cause Thunderbird to crash or, potentially, execute arbitrary
code with the privileges of the user running Thunderbird (CVE-2013-1682,
CVE-2013-1684, CVE-2013-1685, CVE-2013-1686, CVE-2013-1687, CVE-2013-1690).

It was found that Thunderbird allowed data to be sent in the body of
XMLHttpRequest (XHR) HEAD requests. In some cases this could allow
attackers to conduct Cross-Site Request Forgery (CSRF) attacks
(CVE-2013-1692).

Timing differences in the way Thunderbird processed SVG image files could
allow an attacker to read data across domains, potentially leading to
information disclosure (CVE-2013-1693).

Two flaws were found in the way Thunderbird implemented some of its
internal structures (called wrappers). An attacker could use these flaws to
bypass some restrictions placed on them. This could lead to unexpected
behavior or a potentially exploitable crash (CVE-2013-1694, CVE-2013-1697).");

  script_tag(name:"affected", value:"'firefox, firefox-l10n, thunderbird, thunderbird-l10n' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-af", rpm:"firefox-af~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ar", rpm:"firefox-ar~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ast", rpm:"firefox-ast~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-be", rpm:"firefox-be~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bg", rpm:"firefox-bg~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bn_BD", rpm:"firefox-bn_BD~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bn_IN", rpm:"firefox-bn_IN~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-br", rpm:"firefox-br~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bs", rpm:"firefox-bs~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ca", rpm:"firefox-ca~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cs", rpm:"firefox-cs~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cy", rpm:"firefox-cy~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-da", rpm:"firefox-da~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-de", rpm:"firefox-de~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-devel", rpm:"firefox-devel~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-el", rpm:"firefox-el~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_GB", rpm:"firefox-en_GB~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_ZA", rpm:"firefox-en_ZA~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eo", rpm:"firefox-eo~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_AR", rpm:"firefox-es_AR~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_CL", rpm:"firefox-es_CL~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_ES", rpm:"firefox-es_ES~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_MX", rpm:"firefox-es_MX~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-et", rpm:"firefox-et~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eu", rpm:"firefox-eu~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fa", rpm:"firefox-fa~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fi", rpm:"firefox-fi~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fr", rpm:"firefox-fr~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fy", rpm:"firefox-fy~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ga_IE", rpm:"firefox-ga_IE~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gd", rpm:"firefox-gd~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gl", rpm:"firefox-gl~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gu_IN", rpm:"firefox-gu_IN~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-he", rpm:"firefox-he~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hi", rpm:"firefox-hi~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hr", rpm:"firefox-hr~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hu", rpm:"firefox-hu~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hy", rpm:"firefox-hy~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-id", rpm:"firefox-id~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-is", rpm:"firefox-is~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-it", rpm:"firefox-it~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ja", rpm:"firefox-ja~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kk", rpm:"firefox-kk~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kn", rpm:"firefox-kn~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ko", rpm:"firefox-ko~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ku", rpm:"firefox-ku~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-l10n", rpm:"firefox-l10n~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lg", rpm:"firefox-lg~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lt", rpm:"firefox-lt~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lv", rpm:"firefox-lv~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mai", rpm:"firefox-mai~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mk", rpm:"firefox-mk~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ml", rpm:"firefox-ml~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mr", rpm:"firefox-mr~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nb_NO", rpm:"firefox-nb_NO~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nl", rpm:"firefox-nl~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nn_NO", rpm:"firefox-nn_NO~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nso", rpm:"firefox-nso~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-or", rpm:"firefox-or~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pa_IN", rpm:"firefox-pa_IN~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pl", rpm:"firefox-pl~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_BR", rpm:"firefox-pt_BR~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_PT", rpm:"firefox-pt_PT~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ro", rpm:"firefox-ro~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ru", rpm:"firefox-ru~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-si", rpm:"firefox-si~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sk", rpm:"firefox-sk~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sl", rpm:"firefox-sl~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sq", rpm:"firefox-sq~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sr", rpm:"firefox-sr~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sv_SE", rpm:"firefox-sv_SE~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ta", rpm:"firefox-ta~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ta_LK", rpm:"firefox-ta_LK~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-te", rpm:"firefox-te~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-th", rpm:"firefox-th~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-tr", rpm:"firefox-tr~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-uk", rpm:"firefox-uk~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-vi", rpm:"firefox-vi~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_CN", rpm:"firefox-zh_CN~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_TW", rpm:"firefox-zh_TW~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zu", rpm:"firefox-zu~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nsinstall", rpm:"nsinstall~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ar", rpm:"thunderbird-ar~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ast", rpm:"thunderbird-ast~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-be", rpm:"thunderbird-be~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-bg", rpm:"thunderbird-bg~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-bn_BD", rpm:"thunderbird-bn_BD~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-br", rpm:"thunderbird-br~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ca", rpm:"thunderbird-ca~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-cs", rpm:"thunderbird-cs~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-da", rpm:"thunderbird-da~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-de", rpm:"thunderbird-de~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-el", rpm:"thunderbird-el~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-en_GB", rpm:"thunderbird-en_GB~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-enigmail", rpm:"thunderbird-enigmail~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_AR", rpm:"thunderbird-es_AR~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_ES", rpm:"thunderbird-es_ES~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-et", rpm:"thunderbird-et~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-eu", rpm:"thunderbird-eu~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fi", rpm:"thunderbird-fi~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fr", rpm:"thunderbird-fr~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fy", rpm:"thunderbird-fy~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ga", rpm:"thunderbird-ga~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gd", rpm:"thunderbird-gd~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gl", rpm:"thunderbird-gl~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-he", rpm:"thunderbird-he~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hu", rpm:"thunderbird-hu~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-id", rpm:"thunderbird-id~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-is", rpm:"thunderbird-is~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-it", rpm:"thunderbird-it~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ja", rpm:"thunderbird-ja~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ko", rpm:"thunderbird-ko~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-l10n", rpm:"thunderbird-l10n~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-lt", rpm:"thunderbird-lt~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nb_NO", rpm:"thunderbird-nb_NO~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nl", rpm:"thunderbird-nl~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nn_NO", rpm:"thunderbird-nn_NO~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pa_IN", rpm:"thunderbird-pa_IN~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pl", rpm:"thunderbird-pl~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_BR", rpm:"thunderbird-pt_BR~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_PT", rpm:"thunderbird-pt_PT~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ro", rpm:"thunderbird-ro~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ru", rpm:"thunderbird-ru~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-si", rpm:"thunderbird-si~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sk", rpm:"thunderbird-sk~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sl", rpm:"thunderbird-sl~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sq", rpm:"thunderbird-sq~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sv_SE", rpm:"thunderbird-sv_SE~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ta_LK", rpm:"thunderbird-ta_LK~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-tr", rpm:"thunderbird-tr~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-uk", rpm:"thunderbird-uk~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-vi", rpm:"thunderbird-vi~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_CN", rpm:"thunderbird-zh_CN~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_TW", rpm:"thunderbird-zh_TW~17.0.7~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-af", rpm:"firefox-af~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ar", rpm:"firefox-ar~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ast", rpm:"firefox-ast~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-be", rpm:"firefox-be~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bg", rpm:"firefox-bg~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bn_BD", rpm:"firefox-bn_BD~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bn_IN", rpm:"firefox-bn_IN~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-br", rpm:"firefox-br~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bs", rpm:"firefox-bs~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ca", rpm:"firefox-ca~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cs", rpm:"firefox-cs~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cy", rpm:"firefox-cy~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-da", rpm:"firefox-da~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-de", rpm:"firefox-de~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-devel", rpm:"firefox-devel~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-el", rpm:"firefox-el~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_GB", rpm:"firefox-en_GB~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_ZA", rpm:"firefox-en_ZA~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eo", rpm:"firefox-eo~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_AR", rpm:"firefox-es_AR~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_CL", rpm:"firefox-es_CL~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_ES", rpm:"firefox-es_ES~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_MX", rpm:"firefox-es_MX~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-et", rpm:"firefox-et~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eu", rpm:"firefox-eu~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fa", rpm:"firefox-fa~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fi", rpm:"firefox-fi~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fr", rpm:"firefox-fr~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fy", rpm:"firefox-fy~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ga_IE", rpm:"firefox-ga_IE~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gd", rpm:"firefox-gd~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gl", rpm:"firefox-gl~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gu_IN", rpm:"firefox-gu_IN~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-he", rpm:"firefox-he~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hi", rpm:"firefox-hi~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hr", rpm:"firefox-hr~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hu", rpm:"firefox-hu~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hy", rpm:"firefox-hy~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-id", rpm:"firefox-id~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-is", rpm:"firefox-is~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-it", rpm:"firefox-it~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ja", rpm:"firefox-ja~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kk", rpm:"firefox-kk~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kn", rpm:"firefox-kn~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ko", rpm:"firefox-ko~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ku", rpm:"firefox-ku~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-l10n", rpm:"firefox-l10n~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lg", rpm:"firefox-lg~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lt", rpm:"firefox-lt~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lv", rpm:"firefox-lv~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mai", rpm:"firefox-mai~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mk", rpm:"firefox-mk~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ml", rpm:"firefox-ml~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mr", rpm:"firefox-mr~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nb_NO", rpm:"firefox-nb_NO~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nl", rpm:"firefox-nl~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nn_NO", rpm:"firefox-nn_NO~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nso", rpm:"firefox-nso~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-or", rpm:"firefox-or~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pa_IN", rpm:"firefox-pa_IN~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pl", rpm:"firefox-pl~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_BR", rpm:"firefox-pt_BR~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_PT", rpm:"firefox-pt_PT~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ro", rpm:"firefox-ro~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ru", rpm:"firefox-ru~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-si", rpm:"firefox-si~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sk", rpm:"firefox-sk~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sl", rpm:"firefox-sl~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sq", rpm:"firefox-sq~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sr", rpm:"firefox-sr~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sv_SE", rpm:"firefox-sv_SE~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ta", rpm:"firefox-ta~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ta_LK", rpm:"firefox-ta_LK~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-te", rpm:"firefox-te~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-th", rpm:"firefox-th~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-tr", rpm:"firefox-tr~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-uk", rpm:"firefox-uk~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-vi", rpm:"firefox-vi~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_CN", rpm:"firefox-zh_CN~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_TW", rpm:"firefox-zh_TW~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zu", rpm:"firefox-zu~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nsinstall", rpm:"nsinstall~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ar", rpm:"thunderbird-ar~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ast", rpm:"thunderbird-ast~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-be", rpm:"thunderbird-be~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-bg", rpm:"thunderbird-bg~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-bn_BD", rpm:"thunderbird-bn_BD~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-br", rpm:"thunderbird-br~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ca", rpm:"thunderbird-ca~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-cs", rpm:"thunderbird-cs~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-da", rpm:"thunderbird-da~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-de", rpm:"thunderbird-de~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-el", rpm:"thunderbird-el~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-en_GB", rpm:"thunderbird-en_GB~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-enigmail", rpm:"thunderbird-enigmail~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_AR", rpm:"thunderbird-es_AR~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_ES", rpm:"thunderbird-es_ES~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-et", rpm:"thunderbird-et~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-eu", rpm:"thunderbird-eu~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fi", rpm:"thunderbird-fi~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fr", rpm:"thunderbird-fr~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fy", rpm:"thunderbird-fy~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ga", rpm:"thunderbird-ga~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gd", rpm:"thunderbird-gd~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gl", rpm:"thunderbird-gl~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-he", rpm:"thunderbird-he~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hu", rpm:"thunderbird-hu~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-id", rpm:"thunderbird-id~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-is", rpm:"thunderbird-is~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-it", rpm:"thunderbird-it~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ja", rpm:"thunderbird-ja~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ko", rpm:"thunderbird-ko~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-l10n", rpm:"thunderbird-l10n~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-lt", rpm:"thunderbird-lt~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nb_NO", rpm:"thunderbird-nb_NO~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nl", rpm:"thunderbird-nl~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nn_NO", rpm:"thunderbird-nn_NO~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pa_IN", rpm:"thunderbird-pa_IN~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pl", rpm:"thunderbird-pl~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_BR", rpm:"thunderbird-pt_BR~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_PT", rpm:"thunderbird-pt_PT~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ro", rpm:"thunderbird-ro~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ru", rpm:"thunderbird-ru~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-si", rpm:"thunderbird-si~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sk", rpm:"thunderbird-sk~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sl", rpm:"thunderbird-sl~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sq", rpm:"thunderbird-sq~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sv_SE", rpm:"thunderbird-sv_SE~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ta_LK", rpm:"thunderbird-ta_LK~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-tr", rpm:"thunderbird-tr~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-uk", rpm:"thunderbird-uk~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-vi", rpm:"thunderbird-vi~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_CN", rpm:"thunderbird-zh_CN~17.0.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_TW", rpm:"thunderbird-zh_TW~17.0.7~1.mga3", rls:"MAGEIA3"))) {
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
