# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703437");
  script_cve_id("CVE-2015-7575");
  script_tag(name:"creation_date", value:"2016-01-08 23:00:00 +0000 (Fri, 08 Jan 2016)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3437)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3437");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3437");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3437");
  script_xref(name:"URL", value:"https://www.mitls.org/pages/attacks/SLOTH");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnutls26' package(s) announced via the DSA-3437 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Karthikeyan Bhargavan and Gaetan Leurent at INRIA discovered a flaw in the TLS 1.2 protocol which could allow the MD5 hash function to be used for signing ServerKeyExchange and Client Authentication packets during a TLS handshake. A man-in-the-middle attacker could exploit this flaw to conduct collision attacks to impersonate a TLS server or an authenticated TLS client.

More information can be found at [link moved to references]

For the oldstable distribution (wheezy), this problem has been fixed in version 2.12.20-8+deb7u5.

We recommend that you upgrade your gnutls26 packages.");

  script_tag(name:"affected", value:"'gnutls26' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"gnutls-bin", ver:"3.0.22-3+really2.12.20-8+deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnutls26-doc", ver:"2.12.20-8+deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"guile-gnutls", ver:"3.0.22-3+really2.12.20-8+deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.12.20-8+deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls-openssl27", ver:"2.12.20-8+deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls26", ver:"2.12.20-8+deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.12.20-8+deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutlsxx27", ver:"2.12.20-8+deb7u5", rls:"DEB7"))) {
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
