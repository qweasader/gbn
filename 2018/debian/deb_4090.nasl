# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704090");
  script_cve_id("CVE-2017-16510", "CVE-2017-17091", "CVE-2017-17092", "CVE-2017-17093", "CVE-2017-17094");
  script_tag(name:"creation_date", value:"2018-01-16 23:00:00 +0000 (Tue, 16 Jan 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-22 16:47:20 +0000 (Wed, 22 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-4090-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4090-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4090-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4090");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wordpress");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-4090-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Wordpress, a web blogging tool. They allowed remote attackers to perform SQL injections and various Cross-Side Scripting (XSS) and Server-Side Request Forgery (SSRF) attacks, as well as bypass some access restrictions.

For the oldstable distribution (jessie), these problems have been fixed in version 4.1+dfsg-1+deb8u16.

For the stable distribution (stretch), these problems have been fixed in version 4.7.5+dfsg-2+deb9u2.

We recommend that you upgrade your wordpress packages.

For the detailed security status of wordpress please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"4.1+dfsg-1+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"4.1+dfsg-1+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfifteen", ver:"4.1+dfsg-1+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfourteen", ver:"4.1+dfsg-1+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentythirteen", ver:"4.1+dfsg-1+deb8u16", rls:"DEB8"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"4.7.5+dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"4.7.5+dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfifteen", ver:"4.7.5+dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyseventeen", ver:"4.7.5+dfsg-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentysixteen", ver:"4.7.5+dfsg-2+deb9u2", rls:"DEB9"))) {
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
