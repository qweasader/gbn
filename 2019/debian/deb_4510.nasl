# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704510");
  script_cve_id("CVE-2019-11500");
  script_tag(name:"creation_date", value:"2019-08-30 02:00:15 +0000 (Fri, 30 Aug 2019)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-06 15:15:00 +0000 (Fri, 06 Sep 2019)");

  script_name("Debian: Security Advisory (DSA-4510-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4510-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4510-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4510");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dovecot");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dovecot' package(s) announced via the DSA-4510-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nick Roessler and Rafi Rubin discovered that the IMAP and ManageSieve protocol parsers in the Dovecot email server do not properly validate input (both pre- and post-login). A remote attacker can take advantage of this flaw to trigger out of bounds heap memory writes, leading to information leaks or potentially the execution of arbitrary code.

For the oldstable distribution (stretch), this problem has been fixed in version 1:2.2.27-3+deb9u5.

For the stable distribution (buster), this problem has been fixed in version 1:2.3.4.1-5+deb10u1.

We recommend that you upgrade your dovecot packages.

For the detailed security status of dovecot please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'dovecot' package(s) on Debian 9, Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-auth-lua", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-core", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-dev", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-gssapi", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-ldap", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-lmtpd", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-lucene", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-managesieved", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-mysql", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-pgsql", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-sieve", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-solr", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-sqlite", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-submissiond", ver:"1:2.3.4.1-5+deb10u1", rls:"DEB10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-core", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-dbg", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-dev", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-gssapi", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-ldap", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-lmtpd", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-lucene", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-managesieved", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-mysql", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-pgsql", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-sieve", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-solr", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-sqlite", ver:"1:2.2.27-3+deb9u5", rls:"DEB9"))) {
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
