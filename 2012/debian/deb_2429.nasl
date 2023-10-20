# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71233");
  script_cve_id("CVE-2011-2262", "CVE-2012-0075", "CVE-2012-0087", "CVE-2012-0101", "CVE-2012-0102", "CVE-2012-0112", "CVE-2012-0113", "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0118", "CVE-2012-0119", "CVE-2012-0120", "CVE-2012-0484", "CVE-2012-0485", "CVE-2012-0490", "CVE-2012-0492");
  script_tag(name:"creation_date", value:"2012-04-30 11:54:07 +0000 (Mon, 30 Apr 2012)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2429)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2429");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2429");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2429");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-5.1' package(s) announced via the DSA-2429 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Due to the non-disclosure of security patch information from Oracle, we are forced to ship an upstream version update of MySQL 5.1. There are several known incompatible changes, which are listed in /usr/share/doc/mysql-server/NEWS.Debian.gz.

Several security vulnerabilities were discovered in MySQL, a database management system. The vulnerabilities are addressed by upgrading MySQL to a new upstream version, 5.1.61, which includes additional changes, such as performance improvements and corrections for data loss defects. These changes are described in the MySQL release notes at: .

For the stable distribution (squeeze), these problems have been fixed in version 5.1.61-0+squeeze1.

For the unstable distribution (sid), these problems have been fixed in version 5.1.61-2.

We recommend that you upgrade your mysql-5.1 packages.");

  script_tag(name:"affected", value:"'mysql-5.1' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient-dev", ver:"5.1.61-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient16", ver:"5.1.61-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqld-dev", ver:"5.1.61-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqld-pic", ver:"5.1.61-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client", ver:"5.1.61-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client-5.1", ver:"5.1.61-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common", ver:"5.1.61-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server", ver:"5.1.61-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.61-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-core-5.1", ver:"5.1.61-0+squeeze1", rls:"DEB6"))) {
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
