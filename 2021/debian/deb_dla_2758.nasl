# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892758");
  script_cve_id("CVE-2021-3621");
  script_tag(name:"creation_date", value:"2021-09-16 01:00:08 +0000 (Thu, 16 Sep 2021)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-07 16:18:00 +0000 (Fri, 07 Jan 2022)");

  script_name("Debian: Security Advisory (DLA-2758-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2758-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2758-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/sssd");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sssd' package(s) announced via the DLA-2758-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"One security issue has been discovered in sssd.

The sssctl command was vulnerable to shell command injection via the logs-fetch and cache-expire subcommands. This flaw allows an attacker to trick the root user into running a specially crafted sssctl command, such as via sudo, to gain root access. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.

For Debian 9 stretch, this problem has been fixed in version 1.15.0-3+deb9u2.

We recommend that you upgrade your sssd packages.

For the detailed security status of sssd please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'sssd' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libipa-hbac-dev", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libipa-hbac0", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-sss", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpam-sss", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-idmap-dev", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-idmap0", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-nss-idmap-dev", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-nss-idmap0", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-simpleifp-dev", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-simpleifp0", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsss-sudo", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwbclient-sssd", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwbclient-sssd-dev", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-libipa-hbac", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-libsss-nss-idmap", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-sss", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-libipa-hbac", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-libsss-nss-idmap", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-sss", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-ad", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-ad-common", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-common", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-dbus", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-ipa", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-krb5", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-krb5-common", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-ldap", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-proxy", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sssd-tools", ver:"1.15.0-3+deb9u2", rls:"DEB9"))) {
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
