# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0191");
  script_cve_id("CVE-2018-18511", "CVE-2019-11691", "CVE-2019-11692", "CVE-2019-11693", "CVE-2019-11698", "CVE-2019-5798", "CVE-2019-7317", "CVE-2019-9797", "CVE-2019-9800", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9818", "CVE-2019-9819", "CVE-2019-9820");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-26 16:15:30 +0000 (Fri, 26 Jul 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0191)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0191");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0191.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24864");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/60.7.0/releasenotes/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, firefox-l10n' package(s) announced via the MGASA-2019-0191 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated firefox packages fix security vulnerabilities.

Cross-origin theft of images with ImageBitmapRenderingContext.
(CVE-2018-18511)

Out-of-bounds read in Skia. (CVE-2019-5798)

Use-after-free in png_image_free of libpng library. (CVE-2019-7317)

Cross-origin theft of images with createImageBitmap. (CVE-2019-9797)

Memory safety bugs fixed in Firefox 67, Firefox ESR 60.7, and firefox 60.7.
(CVE-2019-9800)

Type confusion with object groups and UnboxedObjects. (CVE-2019-9816)

Stealing of cross-domain images using canvas. (CVE-2019-9817)

Use-after-free in crash generation server. (CVE-2019-9818)

Compartment mismatch with fetch API. (CVE-2019-9819)

Use-after-free of ChromeEventHandler by DocShell. (CVE-2019-9820)

Use-after-free in XMLHttpRequest. (CVE-2019-11691)

Use-after-free removing listeners in the event listener manager.
(CVE-2019-11692)

Buffer overflow in WebGL bufferdata on Linux. (CVE-2019-11693)

Theft of user history data through drag and drop of hyperlinks to and from
bookmarks. (CVE-2019-11698)");

  script_tag(name:"affected", value:"'firefox, firefox-l10n' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-af", rpm:"firefox-af~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-an", rpm:"firefox-an~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ar", rpm:"firefox-ar~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-as", rpm:"firefox-as~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ast", rpm:"firefox-ast~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-az", rpm:"firefox-az~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bg", rpm:"firefox-bg~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bn_BD", rpm:"firefox-bn_BD~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bn_IN", rpm:"firefox-bn_IN~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-br", rpm:"firefox-br~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bs", rpm:"firefox-bs~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ca", rpm:"firefox-ca~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cs", rpm:"firefox-cs~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cy", rpm:"firefox-cy~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-da", rpm:"firefox-da~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-de", rpm:"firefox-de~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-devel", rpm:"firefox-devel~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-el", rpm:"firefox-el~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_GB", rpm:"firefox-en_GB~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_US", rpm:"firefox-en_US~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_ZA", rpm:"firefox-en_ZA~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eo", rpm:"firefox-eo~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_AR", rpm:"firefox-es_AR~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_CL", rpm:"firefox-es_CL~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_ES", rpm:"firefox-es_ES~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_MX", rpm:"firefox-es_MX~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-et", rpm:"firefox-et~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eu", rpm:"firefox-eu~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fa", rpm:"firefox-fa~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ff", rpm:"firefox-ff~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fi", rpm:"firefox-fi~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fr", rpm:"firefox-fr~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fy_NL", rpm:"firefox-fy_NL~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ga_IE", rpm:"firefox-ga_IE~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gd", rpm:"firefox-gd~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gl", rpm:"firefox-gl~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gu_IN", rpm:"firefox-gu_IN~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-he", rpm:"firefox-he~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hi_IN", rpm:"firefox-hi_IN~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hr", rpm:"firefox-hr~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hsb", rpm:"firefox-hsb~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hu", rpm:"firefox-hu~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hy_AM", rpm:"firefox-hy_AM~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-id", rpm:"firefox-id~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-is", rpm:"firefox-is~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-it", rpm:"firefox-it~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ja", rpm:"firefox-ja~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kk", rpm:"firefox-kk~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-km", rpm:"firefox-km~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kn", rpm:"firefox-kn~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ko", rpm:"firefox-ko~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-l10n", rpm:"firefox-l10n~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lij", rpm:"firefox-lij~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lt", rpm:"firefox-lt~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lv", rpm:"firefox-lv~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mai", rpm:"firefox-mai~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mk", rpm:"firefox-mk~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ml", rpm:"firefox-ml~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mr", rpm:"firefox-mr~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ms", rpm:"firefox-ms~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nb_NO", rpm:"firefox-nb_NO~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nl", rpm:"firefox-nl~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nn_NO", rpm:"firefox-nn_NO~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-or", rpm:"firefox-or~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pa_IN", rpm:"firefox-pa_IN~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pl", rpm:"firefox-pl~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_BR", rpm:"firefox-pt_BR~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_PT", rpm:"firefox-pt_PT~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ro", rpm:"firefox-ro~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ru", rpm:"firefox-ru~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-si", rpm:"firefox-si~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sk", rpm:"firefox-sk~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sl", rpm:"firefox-sl~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sq", rpm:"firefox-sq~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sr", rpm:"firefox-sr~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sv_SE", rpm:"firefox-sv_SE~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ta", rpm:"firefox-ta~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-te", rpm:"firefox-te~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-th", rpm:"firefox-th~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-tr", rpm:"firefox-tr~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-uk", rpm:"firefox-uk~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-uz", rpm:"firefox-uz~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-vi", rpm:"firefox-vi~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-xh", rpm:"firefox-xh~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_CN", rpm:"firefox-zh_CN~60.7.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_TW", rpm:"firefox-zh_TW~60.7.0~1.mga6", rls:"MAGEIA6"))) {
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
