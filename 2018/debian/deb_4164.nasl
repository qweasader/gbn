# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704164");
  script_cve_id("CVE-2017-15710", "CVE-2017-15715", "CVE-2018-1283", "CVE-2018-1301", "CVE-2018-1303", "CVE-2018-1312");
  script_tag(name:"creation_date", value:"2018-04-02 22:00:00 +0000 (Mon, 02 Apr 2018)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 17:45:00 +0000 (Wed, 07 Sep 2022)");

  script_name("Debian: Security Advisory (DSA-4164)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4164");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4164");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4164");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/apache2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache2' package(s) announced via the DSA-4164 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Apache HTTPD server.

CVE-2017-15710

Alex Nichols and Jakob Hirsch reported that mod_authnz_ldap, if configured with AuthLDAPCharsetConfig, could cause an out of bound write if supplied with a crafted Accept-Language header. This could potentially be used for a Denial of Service attack.

CVE-2017-15715

Elar Lang discovered that expression specified in <FilesMatch> could match '$' to a newline character in a malicious filename, rather than matching only the end of the filename. This could be exploited in environments where uploads of some files are externally blocked, but only by matching the trailing portion of the filename.

CVE-2018-1283

When mod_session is configured to forward its session data to CGI applications (SessionEnv on, not the default), a remote user could influence their content by using a Session header.

CVE-2018-1301

Robert Swiecki reported that a specially crafted request could have crashed the Apache HTTP Server, due to an out of bound access after a size limit is reached by reading the HTTP header.

CVE-2018-1303

Robert Swiecki reported that a specially crafted HTTP request header could have crashed the Apache HTTP Server if using mod_cache_socache, due to an out of bound read while preparing data to be cached in shared memory.

CVE-2018-1312

Nicolas Daniels discovered that when generating an HTTP Digest authentication challenge, the nonce sent by mod_auth_digest to prevent replay attacks was not correctly generated using a pseudo-random seed. In a cluster of servers using a common Digest authentication configuration, HTTP requests could be replayed across servers by an attacker without detection.

For the oldstable distribution (jessie), these problems have been fixed in version 2.4.10-10+deb8u12.

For the stable distribution (stretch), these problems have been fixed in version 2.4.25-3+deb9u4.

We recommend that you upgrade your apache2 packages.

For the detailed security status of apache2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-data", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-dev", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-doc", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec-pristine", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-utils", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-macro", ver:"1:2.4.10-10+deb8u12", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-proxy-html", ver:"1:2.4.10-10+deb8u12", rls:"DEB8"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.25-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.25-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-data", ver:"2.4.25-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.4.25-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-dev", ver:"2.4.25-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-doc", ver:"2.4.25-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-ssl-dev", ver:"2.4.25-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.4.25-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec-pristine", ver:"2.4.25-3+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-utils", ver:"2.4.25-3+deb9u4", rls:"DEB9"))) {
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
