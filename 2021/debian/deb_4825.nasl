# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704825");
  script_cve_id("CVE-2020-24386", "CVE-2020-25275");
  script_tag(name:"creation_date", value:"2021-01-05 04:00:08 +0000 (Tue, 05 Jan 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-20 03:15:00 +0000 (Wed, 20 Jan 2021)");

  script_name("Debian: Security Advisory (DSA-4825)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4825");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4825");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4825");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dovecot");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dovecot' package(s) announced via the DSA-4825 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Dovecot email server.

CVE-2020-24386

When imap hibernation is active, an attacker (with valid credentials to access the mail server) can cause Dovecot to discover file system directory structures and access other users' emails via specially crafted commands.

CVE-2020-25275

Innokentii Sennovskiy reported that the mail delivery and parsing in Dovecot can crash when the 10000th MIME part is message/rfc822 (or if the parent was multipart/digest). This flaw was introduced by earlier changes addressing CVE-2020-12100.

For the stable distribution (buster), these problems have been fixed in version 1:2.3.4.1-5+deb10u5.

We recommend that you upgrade your dovecot packages.

For the detailed security status of dovecot please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'dovecot' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-auth-lua", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-core", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-dev", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-gssapi", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-ldap", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-lmtpd", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-lucene", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-managesieved", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-mysql", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-pgsql", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-sieve", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-solr", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-sqlite", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-submissiond", ver:"1:2.3.4.1-5+deb10u5", rls:"DEB10"))) {
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
