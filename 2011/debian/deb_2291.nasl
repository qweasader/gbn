# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70227");
  script_cve_id("CVE-2010-4554", "CVE-2010-4555", "CVE-2011-2023", "CVE-2011-2752", "CVE-2011-2753");
  script_tag(name:"creation_date", value:"2011-09-21 03:47:11 +0000 (Wed, 21 Sep 2011)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2291-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2291-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2291-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2291");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squirrelmail' package(s) announced via the DSA-2291-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various vulnerabilities have been found in SquirrelMail, a webmail application. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2010-4554

SquirrelMail did not prevent page rendering inside a third-party HTML frame, which makes it easier for remote attackers to conduct clickjacking attacks via a crafted web site.

CVE-2010-4555, CVE-2011-2752, CVE-2011-2753 Multiple small bugs in SquirrelMail allowed an attacker to inject malicious script into various pages or alter the contents of user preferences.

CVE-2011-2023

It was possible to inject arbitrary web script or HTML via a crafted STYLE element in an HTML part of an e-mail message.

For the oldstable distribution (lenny), these problems have been fixed in version 1.4.15-4+lenny5.

For the stable distribution (squeeze), these problems have been fixed in version 1.4.21-2.

For the testing (wheezy) and unstable distribution (sid), these problems have been fixed in version 1.4.22-1.

We recommend that you upgrade your squirrelmail packages.");

  script_tag(name:"affected", value:"'squirrelmail' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"squirrelmail", ver:"2:1.4.15-4+lenny5", rls:"DEB5"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"squirrelmail", ver:"2:1.4.21-2", rls:"DEB6"))) {
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
