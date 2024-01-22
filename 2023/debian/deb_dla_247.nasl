# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.247");
  script_cve_id("CVE-2014-8176", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792", "CVE-2015-4000");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:29:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DLA-247-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-247-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/DLA-247-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DLA-247-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in OpenSSL, a Secure Sockets Layer toolkit.

CVE-2014-8176

Praveen Kariyanahalli, Ivan Fratric and Felix Groebert discovered that an invalid memory free could be triggered when buffering DTLS data. This could allow remote attackers to cause a denial of service (crash) or potentially execute arbitrary code. This issue only affected the oldstable distribution (wheezy).

CVE-2015-1789

Robert Swiecki and Hanno Bock discovered that the X509_cmp_time function could read a few bytes out of bounds. This could allow remote attackers to cause a denial of service (crash) via crafted certificates and CRLs.

CVE-2015-1790

Michal Zalewski discovered that the PKCS#7 parsing code did not properly handle missing content which could lead to a NULL pointer dereference. This could allow remote attackers to cause a denial of service (crash) via crafted ASN.1-encoded PKCS#7 blobs.

CVE-2015-1791

Emilia Kasper discovered that a race condition could occur due to incorrect handling of NewSessionTicket in a multi-threaded client, leading to a double free. This could allow remote attackers to cause a denial of service (crash).

CVE-2015-1792

Johannes Bauer discovered that the CMS code could enter an infinite loop when verifying a signedData message, if presented with an unknown hash function OID. This could allow remote attackers to cause a denial of service.

Additionally OpenSSL will now reject handshakes using DH parameters shorter than 768 bits as a countermeasure against the Logjam attack (CVE-2015-4000).");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8o-4squeeze21", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8o-4squeeze21", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8o-4squeeze21", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8o-4squeeze21", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"0.9.8o-4squeeze21", rls:"DEB6"))) {
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
