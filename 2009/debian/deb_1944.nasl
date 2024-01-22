# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66456");
  script_cve_id("CVE-2009-3585", "CVE-2009-4151");
  script_tag(name:"creation_date", value:"2009-12-09 23:23:54 +0000 (Wed, 09 Dec 2009)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1944-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1944-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1944-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1944");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'request-tracker3.4, request-tracker3.6' package(s) announced via the DSA-1944-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mikal Gule discovered that request-tracker, an extensible trouble-ticket tracking system, is prone to an attack, where an attacker with access to the same domain can hijack a user's RT session.

For the oldstable distribution (etch), this problem has been fixed in version 3.6.1-4+etch1 of request-tracker3.6 and version 3.4.5-2+etch1 of request-tracker3.4.

For the stable distribution (lenny), this problem has been fixed in version 3.6.7-5+lenny3.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 3.6.9-2.

We recommend that you upgrade your request-tracker packages.");

  script_tag(name:"affected", value:"'request-tracker3.4, request-tracker3.6' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker3.4", ver:"3.4.5-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker3.6", ver:"3.6.1-4+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.4-apache", ver:"3.4.5-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.4-apache2", ver:"3.4.5-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.4-clients", ver:"3.4.5-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.6-apache", ver:"3.6.1-4+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.6-apache2", ver:"3.6.1-4+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.6-clients", ver:"3.6.1-4+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker3.6", ver:"3.6.7-5+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.6-apache2", ver:"3.6.7-5+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.6-clients", ver:"3.6.7-5+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.6-db-mysql", ver:"3.6.7-5+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.6-db-postgresql", ver:"3.6.7-5+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.6-db-sqlite", ver:"3.6.7-5+lenny3", rls:"DEB5"))) {
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
