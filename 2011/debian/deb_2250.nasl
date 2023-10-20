# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69957");
  script_cve_id("CVE-2011-1756");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2250)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2250");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2250");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2250");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'citadel' package(s) announced via the DSA-2250 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Wouter Coekaerts discovered that the Jabber server component of Citadel, a complete and feature-rich groupware server, is vulnerable to the so-called billion laughs attack because it does not prevent entity expansion on received data. This allows an attacker to perform denial of service attacks against the service by sending specially crafted XML data to it.

For the oldstable distribution (lenny), this problem has been fixed in version 7.37-8+lenny1.

For the stable distribution (squeeze), this problem has been fixed in version 7.83-2squeeze2.

For the testing (wheezy) and unstable (sid) distributions, this problem will be fixed soon.

We recommend that you upgrade your citadel packages.");

  script_tag(name:"affected", value:"'citadel' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"citadel-client", ver:"7.37-8+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"citadel-common", ver:"7.37-8+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"citadel-doc", ver:"7.37-8+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"citadel-mta", ver:"7.37-8+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"citadel-server", ver:"7.37-8+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"citadel-suite", ver:"7.37-8+lenny1", rls:"DEB5"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"citadel-client", ver:"7.83-2squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"citadel-dbg", ver:"7.83-2squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"citadel-doc", ver:"7.83-2squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"citadel-mta", ver:"7.83-2squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"citadel-server", ver:"7.83-2squeeze2", rls:"DEB6"))) {
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
