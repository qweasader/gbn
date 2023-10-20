# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703303");
  script_cve_id("CVE-2015-3258", "CVE-2015-3279");
  script_tag(name:"creation_date", value:"2015-07-06 22:00:00 +0000 (Mon, 06 Jul 2015)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3303)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3303");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3303");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3303");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cups-filters' package(s) announced via the DSA-3303 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the texttopdf utility, part of cups-filters, was susceptible to multiple heap-based buffer overflows due to improper handling of print jobs with a specially crafted line size. This could allow remote attackers to crash texttopdf or possibly execute arbitrary code.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.0.18-2.1+deb7u2.

For the stable distribution (jessie), these problems have been fixed in version 1.0.61-5+deb8u1.

For the unstable distribution (sid), these problems have been fixed in version 1.0.71-1.

We recommend that you upgrade your cups-filters packages.");

  script_tag(name:"affected", value:"'cups-filters' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cups-filters", ver:"1.0.18-2.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsfilters-dev", ver:"1.0.18-2.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsfilters1", ver:"1.0.18-2.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"cups-browsed", ver:"1.0.61-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-filters", ver:"1.0.61-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-filters-core-drivers", ver:"1.0.61-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsfilters-dev", ver:"1.0.61-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcupsfilters1", ver:"1.0.61-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfontembed-dev", ver:"1.0.61-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfontembed1", ver:"1.0.61-5+deb8u1", rls:"DEB8"))) {
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
