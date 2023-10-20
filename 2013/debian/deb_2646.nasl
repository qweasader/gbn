# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702646");
  script_cve_id("CVE-2013-1842", "CVE-2013-1843");
  script_tag(name:"creation_date", value:"2013-03-14 23:00:00 +0000 (Thu, 14 Mar 2013)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2646)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2646");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2646");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2646");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'typo3-src' package(s) announced via the DSA-2646 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"TYPO3, a PHP-based content management system, was found vulnerable to several vulnerabilities.

CVE-2013-1842

Helmut Hummel and Markus Opahle discovered that the Extbase database layer was not correctly sanitizing user input when using the Query object model. This can lead to SQL injection by a malicious user inputing crafted relation values.

CVE-2013-1843

Missing user input validation in the access tracking mechanism could lead to arbitrary URL redirection.

Note: the fix will break already published links. Upstream advisory TYPO3-CORE-SA-2013-001 has more information on how to mitigate that.

For the stable distribution (squeeze), these problems have been fixed in version 4.3.9+dfsg1-1+squeeze8.

For the testing distribution (wheezy), these problems have been fixed in version 4.5.19+dfsg1-5.

For the unstable distribution (sid), these problems have been fixed in version 4.5.19+dfsg1-5.

We recommend that you upgrade your typo3-src packages.");

  script_tag(name:"affected", value:"'typo3-src' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"typo3", ver:"4.3.9+dfsg1-1+squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"typo3-database", ver:"4.3.9+dfsg1-1+squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"typo3-src-4.3", ver:"4.3.9+dfsg1-1+squeeze8", rls:"DEB6"))) {
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
