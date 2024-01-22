# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705287");
  script_cve_id("CVE-2021-3671", "CVE-2021-44758", "CVE-2022-3437", "CVE-2022-41916", "CVE-2022-42898", "CVE-2022-44640");
  script_tag(name:"creation_date", value:"2022-11-24 02:00:20 +0000 (Thu, 24 Nov 2022)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 18:28:00 +0000 (Wed, 04 Jan 2023)");

  script_name("Debian: Security Advisory (DSA-5287-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5287-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5287-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5287");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/heimdal");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'heimdal' package(s) announced via the DSA-5287-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Heimdal, an implementation of Kerberos 5 that aims to be compatible with MIT Kerberos.

CVE-2021-3671

Joseph Sutton discovered that the Heimdal KDC does not validate that the server name in the TGS-REQ is present before dereferencing, which may result in denial of service.

CVE-2021-44758

It was discovered that Heimdal is prone to a NULL dereference in acceptors where an initial SPNEGO token that has no acceptable mechanisms, which may result in denial of service for a server application that uses SPNEGO.

CVE-2022-3437

Several buffer overflow flaws and non-constant time leaks were discovered when using 1DES, 3DES or RC4 (arcfour).

CVE-2022-41916

An out-of-bounds memory access was discovered when Heimdal normalizes Unicode, which may result in denial of service.

CVE-2022-42898

It was discovered that integer overflows in PAC parsing may result in denial of service for Heimdal KDCs or possibly Heimdal servers.

CVE-2022-44640

It was discovered that the Heimdal's ASN.1 compiler generates code that allows specially crafted DER encodings to invoke an invalid free on the decoded structure upon decode error, which may result in remote code execution in the Heimdal KDC.

For the stable distribution (bullseye), these problems have been fixed in version 7.7.0+dfsg-2+deb11u2.

We recommend that you upgrade your heimdal packages.

For the detailed security status of heimdal please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'heimdal' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-dev", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-docs", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kcm", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kdc", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-multidev", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libasn1-8-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhcrypto4-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdb9-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheimbase1-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheimntlm0-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhx509-5-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5clnt7-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5srv8-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkafs0-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkdc2-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libotp0-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroken18-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsl0-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwind0-heimdal", ver:"7.7.0+dfsg-2+deb11u2", rls:"DEB11"))) {
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
