# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891806");
  script_cve_id("CVE-2018-18511", "CVE-2019-11691", "CVE-2019-11692", "CVE-2019-11693", "CVE-2019-11698", "CVE-2019-5798", "CVE-2019-7317", "CVE-2019-9797", "CVE-2019-9800", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9819", "CVE-2019-9820");
  script_tag(name:"creation_date", value:"2019-05-28 02:00:16 +0000 (Tue, 28 May 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-26 16:15:30 +0000 (Fri, 26 Jul 2019)");

  script_name("Debian: Security Advisory (DLA-1806-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1806-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1806-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'thunderbird' package(s) announced via the DLA-1806-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Thunderbird: Multiple vulnerabilities may lead to the execution of arbitrary code or denial of service.

For Debian 8 Jessie, these problems have been fixed in version 1:60.7.0-1~deb8u1.

We recommend that you upgrade your thunderbird packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"calendar-google-provider", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-all", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ar", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ast", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-be", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-bg", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-br", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ca", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-cs", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-da", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-de", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-dsb", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-el", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-en-gb", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-es-ar", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-es-es", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-et", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-eu", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-fi", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-fr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-fy-nl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ga-ie", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-gd", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-gl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-he", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-hr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-hsb", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-hu", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-hy-am", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-id", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-is", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-it", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ja", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-kab", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ko", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-lt", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-nb-no", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-nl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-nn-no", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-pl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-pt-br", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-pt-pt", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-rm", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ro", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-ru", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-si", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-sk", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-sl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-sq", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-sr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-sv-se", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-tr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-uk", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-vi", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-zh-cn", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-l10n-zh-tw", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-extension", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ar", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ast", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-be", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-bg", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-br", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ca", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-cs", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-cy", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-da", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-de", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-dsb", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-el", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-en-gb", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-es-ar", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-es-es", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-et", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-eu", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-fi", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-fr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-fy-nl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ga-ie", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-gd", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-gl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-he", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-hr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-hsb", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-hu", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-hy-am", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-id", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-is", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-it", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ja", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-kab", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ko", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-lt", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-nb-no", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-nl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-nn-no", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-pl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-pt-br", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-pt-pt", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-rm", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ro", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-ru", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-si", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-sk", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-sl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-sq", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-sr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-sv-se", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-tr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-uk", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-vi", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-zh-cn", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceowl-l10n-zh-tw", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ar", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ast", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-be", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-bg", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-br", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ca", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-cs", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-cy", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-da", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-de", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-dsb", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-el", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-en-gb", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-es-ar", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-es-es", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-et", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-eu", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-fi", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-fr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-fy-nl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ga-ie", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-gd", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-gl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-he", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-hr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-hsb", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-hu", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-hy-am", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-id", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-is", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-it", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ja", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-kab", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-kk", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ko", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-lt", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ms", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-nb-no", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-nl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-nn-no", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-pl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-pt-br", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-pt-pt", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-rm", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ro", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-ru", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-si", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-sk", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-sl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-sq", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-sr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-sv-se", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-tr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-uk", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-vi", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-zh-cn", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lightning-l10n-zh-tw", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-dbg", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-all", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ar", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ast", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-be", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-bg", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-br", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ca", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-cs", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-cy", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-da", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-de", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-dsb", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-el", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-en-gb", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-es-ar", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-es-es", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-et", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-eu", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-fi", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-fr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-fy-nl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ga-ie", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-gd", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-gl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-he", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-hr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-hsb", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-hu", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-hy-am", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-id", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-is", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-it", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ja", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-kab", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-kk", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ko", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-lt", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ms", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-nb-no", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-nl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-nn-no", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-pl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-pt-br", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-pt-pt", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-rm", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ro", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-ru", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-si", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sk", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sl", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sq", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-sv-se", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-tr", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-uk", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-vi", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-zh-cn", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-l10n-zh-tw", ver:"1:60.7.0-1~deb8u1", rls:"DEB8"))) {
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
