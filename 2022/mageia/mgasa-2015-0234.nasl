# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0234");
  script_cve_id("CVE-2015-2708", "CVE-2015-2710", "CVE-2015-2713", "CVE-2015-2716", "CVE-2015-3414", "CVE-2015-3415", "CVE-2015-3416");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0234)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0234");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0234.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/05/12/7");
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/mbs2/MDVSA-2015%3A217/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15756");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15920");
  script_xref(name:"URL", value:"https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.18.1_release_notes");
  script_xref(name:"URL", value:"https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.19_release_notes");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2015-0988.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2015-1012.html");
  script_xref(name:"URL", value:"https://sqlite.org/changes.html");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-46/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-48/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-51/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-54/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox-esr/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/known-vulnerabilities/thunderbird/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, firefox-l10n, nss, rootcerts, sqlite3, thunderbird, thunderbird-l10n' package(s) announced via the MGASA-2015-0234 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated firefox, thunderbird, and sqlite3 packages fix security
vulnerabilities:

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox or Thunderbird to
crash or, potentially, execute arbitrary code with the privileges of the
user running it (CVE-2015-2708, CVE-2015-2710, CVE-2015-2713).

A heap-based buffer overflow flaw was found in the way Firefox and
Thunderbird processed compressed XML data. An attacker could create
specially crafted compressed XML content that, when processed by Firefox
or Thunderbird, could cause it to crash or execute arbitrary code with the
privileges of the user running it (CVE-2015-2716).

SQLite before 3.8.9 does not properly implement the dequoting of
collation-sequence names, which allows context-dependent attackers to
cause a denial of service (uninitialized memory access and application
crash) or possibly have unspecified other impact via a crafted COLLATE
clause, as demonstrated by COLLATE at the end of a SELECT statement
(CVE-2015-3414).

The sqlite3VdbeExec function in vdbe.c in SQLite before 3.8.9
does not properly implement comparison operators, which allows
context-dependent attackers to cause a denial of service (invalid
free operation) or possibly have unspecified other impact via a
crafted CHECK clause, as demonstrated by CHECK(0&O>O) in a CREATE
TABLE statement (CVE-2015-3415).

The sqlite3VXPrintf function in printf.c in SQLite before 3.8.9 does
not properly handle precision and width values during floating-point
conversions, which allows context-dependent attackers to cause a
denial of service (integer overflow and stack-based buffer overflow)
or possibly have unspecified other impact via large integers in a
crafted printf function call in a SELECT statement (CVE-2015-3416).

The sqlite3 package has been updated to version 3.10.8, fixing the
CVE-2015-3414, CVE-2015-3415, and CVE-2015-3416 security issues, also
fixing heap overflow and other possible issues found by fuzzing, as well
as containing many other bug fixes and enhancements.

The nss package has been updated to version 3.19, containing multiple root
certificate updates, security enhancements, and other bug fixes.");

  script_tag(name:"affected", value:"'firefox, firefox-l10n, nss, rootcerts, sqlite3, thunderbird, thunderbird-l10n' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-af", rpm:"firefox-af~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ar", rpm:"firefox-ar~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-as", rpm:"firefox-as~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ast", rpm:"firefox-ast~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-be", rpm:"firefox-be~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bg", rpm:"firefox-bg~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bn_BD", rpm:"firefox-bn_BD~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bn_IN", rpm:"firefox-bn_IN~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-br", rpm:"firefox-br~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bs", rpm:"firefox-bs~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ca", rpm:"firefox-ca~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cs", rpm:"firefox-cs~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-csb", rpm:"firefox-csb~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cy", rpm:"firefox-cy~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-da", rpm:"firefox-da~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-de", rpm:"firefox-de~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-devel", rpm:"firefox-devel~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-el", rpm:"firefox-el~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_GB", rpm:"firefox-en_GB~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_ZA", rpm:"firefox-en_ZA~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eo", rpm:"firefox-eo~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_AR", rpm:"firefox-es_AR~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_CL", rpm:"firefox-es_CL~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_ES", rpm:"firefox-es_ES~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_MX", rpm:"firefox-es_MX~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-et", rpm:"firefox-et~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eu", rpm:"firefox-eu~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fa", rpm:"firefox-fa~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ff", rpm:"firefox-ff~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fi", rpm:"firefox-fi~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fr", rpm:"firefox-fr~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fy", rpm:"firefox-fy~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ga_IE", rpm:"firefox-ga_IE~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gd", rpm:"firefox-gd~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gl", rpm:"firefox-gl~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gu_IN", rpm:"firefox-gu_IN~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-he", rpm:"firefox-he~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hi", rpm:"firefox-hi~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hr", rpm:"firefox-hr~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hu", rpm:"firefox-hu~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hy", rpm:"firefox-hy~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-id", rpm:"firefox-id~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-is", rpm:"firefox-is~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-it", rpm:"firefox-it~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ja", rpm:"firefox-ja~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kk", rpm:"firefox-kk~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-km", rpm:"firefox-km~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kn", rpm:"firefox-kn~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ko", rpm:"firefox-ko~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ku", rpm:"firefox-ku~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-l10n", rpm:"firefox-l10n~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lij", rpm:"firefox-lij~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lt", rpm:"firefox-lt~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lv", rpm:"firefox-lv~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mai", rpm:"firefox-mai~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mk", rpm:"firefox-mk~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ml", rpm:"firefox-ml~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mr", rpm:"firefox-mr~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nb_NO", rpm:"firefox-nb_NO~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nl", rpm:"firefox-nl~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nn_NO", rpm:"firefox-nn_NO~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-or", rpm:"firefox-or~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pa_IN", rpm:"firefox-pa_IN~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pl", rpm:"firefox-pl~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_BR", rpm:"firefox-pt_BR~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_PT", rpm:"firefox-pt_PT~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ro", rpm:"firefox-ro~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ru", rpm:"firefox-ru~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-si", rpm:"firefox-si~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sk", rpm:"firefox-sk~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sl", rpm:"firefox-sl~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sq", rpm:"firefox-sq~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sr", rpm:"firefox-sr~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sv_SE", rpm:"firefox-sv_SE~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ta", rpm:"firefox-ta~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-te", rpm:"firefox-te~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-th", rpm:"firefox-th~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-tr", rpm:"firefox-tr~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-uk", rpm:"firefox-uk~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-vi", rpm:"firefox-vi~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_CN", rpm:"firefox-zh_CN~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_TW", rpm:"firefox-zh_TW~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zu", rpm:"firefox-zu~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lemon", rpm:"lemon~3.8.10.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nss-devel", rpm:"lib64nss-devel~3.19.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nss-static-devel", rpm:"lib64nss-static-devel~3.19.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nss3", rpm:"lib64nss3~3.19.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite3-devel", rpm:"lib64sqlite3-devel~3.8.10.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite3-static-devel", rpm:"lib64sqlite3-static-devel~3.8.10.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite3_0", rpm:"lib64sqlite3_0~3.8.10.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss-devel", rpm:"libnss-devel~3.19.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss-static-devel", rpm:"libnss-static-devel~3.19.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss3", rpm:"libnss3~3.19.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-devel", rpm:"libsqlite3-devel~3.8.10.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-static-devel", rpm:"libsqlite3-static-devel~3.8.10.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3_0", rpm:"libsqlite3_0~3.8.10.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nsinstall", rpm:"nsinstall~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.19.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-doc", rpm:"nss-doc~3.19.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rootcerts", rpm:"rootcerts~20150420.00~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rootcerts-java", rpm:"rootcerts-java~20150420.00~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3", rpm:"sqlite3~3.8.10.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-tcl", rpm:"sqlite3-tcl~3.8.10.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-tools", rpm:"sqlite3-tools~3.8.10.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ar", rpm:"thunderbird-ar~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ast", rpm:"thunderbird-ast~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-be", rpm:"thunderbird-be~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-bg", rpm:"thunderbird-bg~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-bn_BD", rpm:"thunderbird-bn_BD~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-br", rpm:"thunderbird-br~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ca", rpm:"thunderbird-ca~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-cs", rpm:"thunderbird-cs~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-da", rpm:"thunderbird-da~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-de", rpm:"thunderbird-de~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-el", rpm:"thunderbird-el~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-en_GB", rpm:"thunderbird-en_GB~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-enigmail", rpm:"thunderbird-enigmail~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_AR", rpm:"thunderbird-es_AR~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_ES", rpm:"thunderbird-es_ES~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-et", rpm:"thunderbird-et~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-eu", rpm:"thunderbird-eu~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fi", rpm:"thunderbird-fi~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fr", rpm:"thunderbird-fr~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fy", rpm:"thunderbird-fy~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ga", rpm:"thunderbird-ga~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gd", rpm:"thunderbird-gd~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gl", rpm:"thunderbird-gl~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-he", rpm:"thunderbird-he~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hr", rpm:"thunderbird-hr~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hu", rpm:"thunderbird-hu~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hy", rpm:"thunderbird-hy~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-id", rpm:"thunderbird-id~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-is", rpm:"thunderbird-is~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-it", rpm:"thunderbird-it~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ja", rpm:"thunderbird-ja~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ko", rpm:"thunderbird-ko~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-l10n", rpm:"thunderbird-l10n~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-lt", rpm:"thunderbird-lt~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nb_NO", rpm:"thunderbird-nb_NO~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nl", rpm:"thunderbird-nl~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nn_NO", rpm:"thunderbird-nn_NO~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pa_IN", rpm:"thunderbird-pa_IN~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pl", rpm:"thunderbird-pl~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_BR", rpm:"thunderbird-pt_BR~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_PT", rpm:"thunderbird-pt_PT~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ro", rpm:"thunderbird-ro~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ru", rpm:"thunderbird-ru~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-si", rpm:"thunderbird-si~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sk", rpm:"thunderbird-sk~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sl", rpm:"thunderbird-sl~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sq", rpm:"thunderbird-sq~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sv_SE", rpm:"thunderbird-sv_SE~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ta_LK", rpm:"thunderbird-ta_LK~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-tr", rpm:"thunderbird-tr~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-uk", rpm:"thunderbird-uk~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-vi", rpm:"thunderbird-vi~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_CN", rpm:"thunderbird-zh_CN~31.7.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_TW", rpm:"thunderbird-zh_TW~31.7.0~1.mga4", rls:"MAGEIA4"))) {
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
