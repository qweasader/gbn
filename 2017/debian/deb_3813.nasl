# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703813");
  script_cve_id("CVE-2016-8714");
  script_tag(name:"creation_date", value:"2017-03-18 23:00:00 +0000 (Sat, 18 Mar 2017)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-14 13:52:00 +0000 (Wed, 14 Dec 2022)");

  script_name("Debian: Security Advisory (DSA-3813-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3813-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3813-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3813");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'r-base' package(s) announced via the DSA-3813-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cory Duplantis discovered a buffer overflow in the R programming language. A malformed encoding file may lead to the execution of arbitrary code during PDF generation.

For the stable distribution (jessie), this problem has been fixed in version 3.1.1-1+deb8u1.

For the upcoming stable distribution (stretch), this problem has been fixed in version 3.3.3-1.

For the unstable distribution (sid), this problem has been fixed in version 3.3.3-1.

We recommend that you upgrade your r-base packages.");

  script_tag(name:"affected", value:"'r-base' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"r-base", ver:"3.1.1-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"r-base-core", ver:"3.1.1-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"r-base-core-dbg", ver:"3.1.1-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"r-base-dev", ver:"3.1.1-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"r-base-html", ver:"3.1.1-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"r-doc-html", ver:"3.1.1-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"r-doc-info", ver:"3.1.1-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"r-doc-pdf", ver:"3.1.1-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"r-mathlib", ver:"3.1.1-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"r-recommended", ver:"3.1.1-1+deb8u1", rls:"DEB8"))) {
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
