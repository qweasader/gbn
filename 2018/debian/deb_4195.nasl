# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704195");
  script_cve_id("CVE-2018-0494");
  script_tag(name:"creation_date", value:"2018-05-07 22:00:00 +0000 (Mon, 07 May 2018)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-15 01:22:00 +0000 (Fri, 15 Mar 2019)");

  script_name("Debian: Security Advisory (DSA-4195-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4195-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4195-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4195");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wget");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wget' package(s) announced via the DSA-4195-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Harry Sintonen discovered that wget, a network utility to retrieve files from the web, does not properly handle 'rn' from continuation lines while parsing the Set-Cookie HTTP header. A malicious web server could use this flaw to inject arbitrary cookies to the cookie jar file, adding new or replacing existing cookie values.

For the oldstable distribution (jessie), this problem has been fixed in version 1.16-1+deb8u5.

For the stable distribution (stretch), this problem has been fixed in version 1.18-5+deb9u2.

We recommend that you upgrade your wget packages.

For the detailed security status of wget please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wget' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wget", ver:"1.16-1+deb8u5", rls:"DEB8"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"wget", ver:"1.18-5+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wget-udeb", ver:"1.18-5+deb9u2", rls:"DEB9"))) {
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
