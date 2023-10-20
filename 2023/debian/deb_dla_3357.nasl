# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3357");
  script_cve_id("CVE-2020-19667", "CVE-2020-25665", "CVE-2020-25666", "CVE-2020-25674", "CVE-2020-25675", "CVE-2020-25676", "CVE-2020-27560", "CVE-2020-27750", "CVE-2020-27751", "CVE-2020-27754", "CVE-2020-27756", "CVE-2020-27757", "CVE-2020-27758", "CVE-2020-27759", "CVE-2020-27760", "CVE-2020-27761", "CVE-2020-27762", "CVE-2020-27763", "CVE-2020-27764", "CVE-2020-27765", "CVE-2020-27766", "CVE-2020-27767", "CVE-2020-27768", "CVE-2020-27769", "CVE-2020-27770", "CVE-2020-27771", "CVE-2020-27772", "CVE-2020-27773", "CVE-2020-27774", "CVE-2020-27775", "CVE-2020-27776", "CVE-2020-29599", "CVE-2021-20224", "CVE-2021-3574", "CVE-2021-3596", "CVE-2022-44267", "CVE-2022-44268");
  script_tag(name:"creation_date", value:"2023-03-13 04:23:52 +0000 (Mon, 13 Mar 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-29 19:40:00 +0000 (Mon, 29 Mar 2021)");

  script_name("Debian: Security Advisory (DLA-3357)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3357");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3357-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/imagemagick");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DLA-3357 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The previous Imagemagick security update caused a regression in some perl packages due to overly restrictive hardening in a policy update (reading from /etc/ was forbidden). This hardening patch has been removed.

For Debian 10 buster, this problem has been fixed in version 8:6.9.10.23+dfsg-2.1+deb10u4.

We recommend that you upgrade your imagemagick packages.

For the detailed security status of imagemagick please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6-common", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6-doc", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16hdri", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-common", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-doc", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-perl", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16hdri-perl", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6-headers", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-8", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-dev", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16hdri-8", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16hdri-dev", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-arch-config", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-headers", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6-extra", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-dev", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-6", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-6-extra", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-dev", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6-headers", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-6", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-dev", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16hdri-6", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16hdri-dev", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.9.10.23+dfsg-2.1+deb10u2", rls:"DEB10"))) {
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
