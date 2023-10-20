# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3449");
  script_cve_id("CVE-2023-0464", "CVE-2023-0465", "CVE-2023-0466", "CVE-2023-2650");
  script_tag(name:"creation_date", value:"2023-06-09 04:28:07 +0000 (Fri, 09 Jun 2023)");
  script_version("2023-08-31T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-08-31 05:05:25 +0000 (Thu, 31 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-29 19:37:00 +0000 (Wed, 29 Mar 2023)");

  script_name("Debian: Security Advisory (DLA-3449)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3449");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3449");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openssl");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DLA-3449 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in OpenSSL, a Secure Sockets Layer toolkit.

CVE-2023-0464

David Benjamin reported a flaw related to the verification of X.509 certificate chains that include policy constraints, which may result in denial of service.

CVE-2023-0465

David Benjamin reported that invalid certificate policies in leaf certificates are silently ignored. A malicious CA could take advantage of this flaw to deliberately assert invalid certificate policies in order to circumvent policy checking on the certificate altogether.

CVE-2023-0466

David Benjamin discovered that the implementation of the X509_VERIFY_PARAM_add0_policy() function does not enable the check which allows certificates with invalid or incorrect policies to pass the certificate verification (contrary to its documentation).

CVE-2023-2650

It was discovered that processing malformed ASN.1 object identifiers or data may result in denial of service.

For Debian 10 buster, these problems have been fixed in version 1.1.1n-0+deb10u5.

We recommend that you upgrade your openssl packages.

For the detailed security status of openssl please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

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

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto1.1-udeb", ver:"1.1.1n-0+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"1.1.1n-0+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-doc", ver:"1.1.1n-0+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1n-0+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1-udeb", ver:"1.1.1n-0+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.1.1n-0+deb10u5", rls:"DEB10"))) {
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
