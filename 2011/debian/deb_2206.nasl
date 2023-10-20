# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69416");
  script_cve_id("CVE-2011-0439", "CVE-2011-0440");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2206)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2206");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2206");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2206");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mahara' package(s) announced via the DSA-2206 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security vulnerabilities have been discovered in Mahara, a fully featured electronic portfolio, weblog, resume builder and social networking system:

CVE-2011-0439

A security review commissioned by a Mahara user discovered that Mahara processes unsanitized input which can lead to cross-site scripting (XSS).

CVE-2011-0440

Mahara Developers discovered that Mahara doesn't check the session key under certain circumstances which can be exploited as cross-site request forgery (CSRF) and can lead to the deletion of blogs.

For the old stable distribution (lenny) these problems have been fixed in version 1.0.4-4+lenny8.

For the stable distribution (squeeze) these problems have been fixed in version 1.2.6-2+squeeze1.

For the unstable distribution (sid) these problems have been fixed in version 1.2.7.

We recommend that you upgrade your mahara package.");

  script_tag(name:"affected", value:"'mahara' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mahara", ver:"1.0.4-4+lenny8", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mahara-apache2", ver:"1.0.4-4+lenny8", rls:"DEB5"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mahara", ver:"1.2.6-2+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mahara-apache2", ver:"1.2.6-2+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mahara-mediaplayer", ver:"1.2.6-2+squeeze1", rls:"DEB6"))) {
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
