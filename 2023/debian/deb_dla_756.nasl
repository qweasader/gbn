# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.756");
  script_cve_id("CVE-2016-10059", "CVE-2016-10060", "CVE-2016-10061", "CVE-2016-10063", "CVE-2016-10064", "CVE-2016-10065", "CVE-2016-10066", "CVE-2016-10067", "CVE-2016-10068", "CVE-2016-10069", "CVE-2016-10070", "CVE-2016-10071", "CVE-2016-7799", "CVE-2016-8677", "CVE-2016-8707", "CVE-2016-8862", "CVE-2016-8866", "CVE-2016-9556", "CVE-2016-9559");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-28 19:22:00 +0000 (Wed, 28 Apr 2021)");

  script_name("Debian: Security Advisory (DLA-756)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-756");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-756");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DLA-756 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Numerous vulnerabilities were discovered in ImageMagick, an image manipulation program. Issues include memory exception, heap, buffer and stack overflows, out of bound reads and missing checks.

For Debian 7 Wheezy, these problems have been fixed in version 8:6.7.7.10-5+deb7u10.

The exact impact of the vulnerabilities is unknown, as they were mostly discovered through fuzzing. We still recommend that you upgrade your imagemagick packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.7.7.10-5+deb7u10", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-common", ver:"8:6.7.7.10-5+deb7u10", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-dbg", ver:"8:6.7.7.10-5+deb7u10", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-doc", ver:"8:6.7.7.10-5+deb7u10", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.7.7.10-5+deb7u10", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++5", ver:"8:6.7.7.10-5+deb7u10", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.7.7.10-5+deb7u10", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore5", ver:"8:6.7.7.10-5+deb7u10", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore5-extra", ver:"8:6.7.7.10-5+deb7u10", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.7.7.10-5+deb7u10", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand5", ver:"8:6.7.7.10-5+deb7u10", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.7.7.10-5+deb7u10", rls:"DEB7"))) {
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
