# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70407");
  script_cve_id("CVE-2011-3208", "CVE-2011-3372");
  script_tag(name:"creation_date", value:"2011-10-16 21:01:53 +0000 (Sun, 16 Oct 2011)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2318)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2318");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2318");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2318");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cyrus-imapd-2.2' package(s) announced via the DSA-2318 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been discovered in cyrus-imapd, a highly scalable mail system designed for use in enterprise environments. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2011-3208

Coverity discovered a stack-based buffer overflow in the NNTP server implementation (nttpd) of cyrus-imapd. An attacker can exploit this flaw via several crafted NNTP commands to execute arbitrary code.

CVE-2011-3372

Stefan Cornelius of Secunia Research discovered that the command processing of the NNTP server implementation (nttpd) of cyrus-imapd is not properly implementing access restrictions for certain commands and is not checking for a complete, successful authentication. An attacker can use this flaw to bypass access restrictions for some commands and, e.g. exploit CVE-2011-3208 without proper authentication.

For the oldstable distribution (lenny), this problem has been fixed in version 2.2_2.2.13-14+lenny5.

For the stable distribution (squeeze), this problem has been fixed in version 2.2_2.2.13-19+squeeze2.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in cyrus-imapd-2.4 version 2.4.12-1.

We recommend that you upgrade your cyrus-imapd-2.2 packages.");

  script_tag(name:"affected", value:"'cyrus-imapd-2.2' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-admin-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-clients-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-common-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-dev-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-doc-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-imapd-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-murder-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-nntpd-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-pop3d-2.2", ver:"2.2.13-14+lenny5", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcyrus-imap-perl22", ver:"2.2.13-14+lenny5", rls:"DEB5"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-admin-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-clients-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-common-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-dev-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-doc-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-imapd-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-murder-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-nntpd-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-pop3d-2.2", ver:"2.2.13-19+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcyrus-imap-perl22", ver:"2.2.13-19+squeeze2", rls:"DEB6"))) {
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
