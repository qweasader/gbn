# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704855");
  script_cve_id("CVE-2019-1551", "CVE-2021-23840", "CVE-2021-23841");
  script_tag(name:"creation_date", value:"2021-02-19 04:00:14 +0000 (Fri, 19 Feb 2021)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Debian: Security Advisory (DSA-4855)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4855");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4855");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4855");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20191206.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20210216.txt");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openssl");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-4855 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in OpenSSL, a Secure Sockets Layer toolkit. An overflow bug in the x64_64 Montgomery squaring procedure, an integer overflow in CipherUpdate and a NULL pointer dereference flaw X509_issuer_and_serial_hash() were found, which could result in denial of service.

Additional details can be found in the upstream advisories [link moved to references] and [link moved to references].

For the stable distribution (buster), these problems have been fixed in version 1.1.1d-0+deb10u5.

We recommend that you upgrade your openssl packages.

For the detailed security status of openssl please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto1.1-udeb", ver:"1.1.1d-0+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"1.1.1d-0+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-doc", ver:"1.1.1d-0+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1d-0+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1-udeb", ver:"1.1.1d-0+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.1.1d-0+deb10u5", rls:"DEB10"))) {
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
