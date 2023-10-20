# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0208");
  script_cve_id("CVE-2020-12387", "CVE-2020-12392", "CVE-2020-12395", "CVE-2020-6831");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-23 19:37:00 +0000 (Thu, 23 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0208)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0208");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0208.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26589");
  script_xref(name:"URL", value:"https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.52_release_notes");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-17/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, firefox-l10n, nss, rootcerts' package(s) announced via the MGASA-2020-0208 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated firefox packages fix security vulnerabilities:

A buffer overflow could occur when parsing and validating SCTP chunks in
WebRTC. This could have led to memory corruption and a potentially
exploitable crash (CVE-2020-6831).

A race condition when running shutdown code for Web Worker led to a
use-after-free vulnerability. This resulted in a potentially exploitable
crash (CVE-2020-12387).

The 'Copy as cURL' feature of Devtools' network tab did not properly escape
the HTTP POST data of a request, which can be controlled by the website.
If a user used the 'Copy as cURL' feature and pasted the command into a
terminal, it could have resulted in the disclosure of local files
(CVE-2020-12392).

Mozilla developers and community members Alexandru Michis, Jason Kratzer,
philipp, Ted Campbell, Bas Schouten, Andre Bargull, and Karl Tomlinson
reported memory safety bugs present in Firefox ESR 68.7. Some of these bugs
showed evidence of memory corruption and we presume that with enough effort
some of these could have been exploited to run arbitrary code
(CVE-2020-12395).

nss has been updated to 3.52.
rootcerts have been updated to drop some obsolete certs fixing support
for nss 3.52.");

  script_tag(name:"affected", value:"'firefox, firefox-l10n, nss, rootcerts' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-af", rpm:"firefox-af~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-an", rpm:"firefox-an~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ar", rpm:"firefox-ar~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ast", rpm:"firefox-ast~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-az", rpm:"firefox-az~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bg", rpm:"firefox-bg~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bn", rpm:"firefox-bn~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-br", rpm:"firefox-br~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bs", rpm:"firefox-bs~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ca", rpm:"firefox-ca~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cs", rpm:"firefox-cs~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cy", rpm:"firefox-cy~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-da", rpm:"firefox-da~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-de", rpm:"firefox-de~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-devel", rpm:"firefox-devel~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-el", rpm:"firefox-el~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_GB", rpm:"firefox-en_GB~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_US", rpm:"firefox-en_US~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eo", rpm:"firefox-eo~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_AR", rpm:"firefox-es_AR~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_CL", rpm:"firefox-es_CL~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_ES", rpm:"firefox-es_ES~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_MX", rpm:"firefox-es_MX~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-et", rpm:"firefox-et~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eu", rpm:"firefox-eu~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fa", rpm:"firefox-fa~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ff", rpm:"firefox-ff~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fi", rpm:"firefox-fi~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fr", rpm:"firefox-fr~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fy_NL", rpm:"firefox-fy_NL~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ga_IE", rpm:"firefox-ga_IE~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gd", rpm:"firefox-gd~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gl", rpm:"firefox-gl~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gu_IN", rpm:"firefox-gu_IN~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-he", rpm:"firefox-he~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hi_IN", rpm:"firefox-hi_IN~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hr", rpm:"firefox-hr~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hsb", rpm:"firefox-hsb~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hu", rpm:"firefox-hu~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hy_AM", rpm:"firefox-hy_AM~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-id", rpm:"firefox-id~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-is", rpm:"firefox-is~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-it", rpm:"firefox-it~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ja", rpm:"firefox-ja~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kk", rpm:"firefox-kk~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-km", rpm:"firefox-km~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kn", rpm:"firefox-kn~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ko", rpm:"firefox-ko~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-l10n", rpm:"firefox-l10n~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lij", rpm:"firefox-lij~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lt", rpm:"firefox-lt~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lv", rpm:"firefox-lv~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mk", rpm:"firefox-mk~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mr", rpm:"firefox-mr~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ms", rpm:"firefox-ms~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nb_NO", rpm:"firefox-nb_NO~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nl", rpm:"firefox-nl~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nn_NO", rpm:"firefox-nn_NO~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pa_IN", rpm:"firefox-pa_IN~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pl", rpm:"firefox-pl~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_BR", rpm:"firefox-pt_BR~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_PT", rpm:"firefox-pt_PT~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ro", rpm:"firefox-ro~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ru", rpm:"firefox-ru~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-si", rpm:"firefox-si~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sk", rpm:"firefox-sk~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sl", rpm:"firefox-sl~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sq", rpm:"firefox-sq~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sr", rpm:"firefox-sr~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sv_SE", rpm:"firefox-sv_SE~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ta", rpm:"firefox-ta~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-te", rpm:"firefox-te~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-th", rpm:"firefox-th~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-tr", rpm:"firefox-tr~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-uk", rpm:"firefox-uk~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-uz", rpm:"firefox-uz~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-vi", rpm:"firefox-vi~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-xh", rpm:"firefox-xh~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_CN", rpm:"firefox-zh_CN~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_TW", rpm:"firefox-zh_TW~68.8.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nss-devel", rpm:"lib64nss-devel~3.52.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nss-static-devel", rpm:"lib64nss-static-devel~3.52.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nss3", rpm:"lib64nss3~3.52.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss-devel", rpm:"libnss-devel~3.52.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss-static-devel", rpm:"libnss-static-devel~3.52.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss3", rpm:"libnss3~3.52.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.52.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-doc", rpm:"nss-doc~3.52.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rootcerts", rpm:"rootcerts~20191126.00~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rootcerts-java", rpm:"rootcerts-java~20191126.00~2.mga7", rls:"MAGEIA7"))) {
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
