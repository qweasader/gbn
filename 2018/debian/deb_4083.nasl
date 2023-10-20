# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704083");
  script_cve_id("CVE-2017-1000472");
  script_tag(name:"creation_date", value:"2018-01-10 23:00:00 +0000 (Wed, 10 Jan 2018)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-04 02:29:00 +0000 (Sun, 04 Feb 2018)");

  script_name("Debian: Security Advisory (DSA-4083)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4083");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4083");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4083");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/poco");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'poco' package(s) announced via the DSA-4083 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stephan Zeisberg discovered that poco, a collection of open source C++ class libraries, did not correctly validate file paths in ZIP archives. An attacker could leverage this flaw to create or overwrite arbitrary files.

For the oldstable distribution (jessie), this problem has been fixed in version 1.3.6p1-5+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 1.7.6+dfsg1-5+deb9u1.

We recommend that you upgrade your poco packages.

For the detailed security status of poco please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'poco' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpoco-dev", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpococrypto9", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpococrypto9-dbg", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocodata9", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocodata9-dbg", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocofoundation9", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocofoundation9-dbg", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocomysql9", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocomysql9-dbg", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoconet9", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoconet9-dbg", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoconetssl9", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoconetssl9-dbg", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocoodbc9", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocoodbc9-dbg", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocosqlite9", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocosqlite9-dbg", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocoutil9", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocoutil9-dbg", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocoxml9", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocoxml9-dbg", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocozip9", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocozip9-dbg", ver:"1.3.6p1-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libpoco-dev", ver:"1.7.6+dfsg1-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpococrypto46", ver:"1.7.6+dfsg1-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocodata46", ver:"1.7.6+dfsg1-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocodatamysql46", ver:"1.7.6+dfsg1-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocodataodbc46", ver:"1.7.6+dfsg1-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocodatasqlite46", ver:"1.7.6+dfsg1-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocofoundation46", ver:"1.7.6+dfsg1-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocomongodb46", ver:"1.7.6+dfsg1-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoconet46", ver:"1.7.6+dfsg1-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoconetssl46", ver:"1.7.6+dfsg1-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocoutil46", ver:"1.7.6+dfsg1-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocoxml46", ver:"1.7.6+dfsg1-5+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpocozip46", ver:"1.7.6+dfsg1-5+deb9u1", rls:"DEB9"))) {
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
