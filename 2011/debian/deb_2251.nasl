# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69958");
  script_cve_id("CVE-2011-1752", "CVE-2011-1783", "CVE-2011-1921");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2251)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2251");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2251");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2251");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'subversion' package(s) announced via the DSA-2251 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Subversion, the version control system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2011-1752

The mod_dav_svn Apache HTTPD server module can be crashed though when asked to deliver baselined WebDAV resources.

CVE-2011-1783

The mod_dav_svn Apache HTTPD server module can trigger a loop which consumes all available memory on the system.

CVE-2011-1921

The mod_dav_svn Apache HTTPD server module may leak to remote users the file contents of files configured to be unreadable by those users.

For the oldstable distribution (lenny), this problem has been fixed in version 1.5.1dfsg1-7.

For the stable distribution (squeeze), this problem has been fixed in version 1.6.12dfsg-6.

For the unstable distribution (sid), this problem has been fixed in version 1.6.17dfsg-1.

We recommend that you upgrade your subversion packages.");

  script_tag(name:"affected", value:"'subversion' package(s) on Debian 5, Debian 6.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.5.1dfsg1-7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.5.1dfsg1-7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.5.1dfsg1-7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-java", ver:"1.5.1dfsg1-7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.5.1dfsg1-7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-ruby", ver:"1.5.1dfsg1-7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-ruby1.8", ver:"1.5.1dfsg1-7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn1", ver:"1.5.1dfsg1-7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-subversion", ver:"1.5.1dfsg1-7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"subversion", ver:"1.5.1dfsg1-7", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"subversion-tools", ver:"1.5.1dfsg1-7", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.12dfsg-6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.6.12dfsg-6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.6.12dfsg-6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-java", ver:"1.6.12dfsg-6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.6.12dfsg-6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-ruby", ver:"1.6.12dfsg-6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn-ruby1.8", ver:"1.6.12dfsg-6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsvn1", ver:"1.6.12dfsg-6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-subversion", ver:"1.6.12dfsg-6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"subversion", ver:"1.6.12dfsg-6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"subversion-tools", ver:"1.6.12dfsg-6", rls:"DEB6"))) {
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
