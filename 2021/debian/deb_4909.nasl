# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704909");
  script_cve_id("CVE-2021-25214", "CVE-2021-25215", "CVE-2021-25216");
  script_tag(name:"creation_date", value:"2021-05-02 03:00:09 +0000 (Sun, 02 May 2021)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-07 14:15:00 +0000 (Mon, 07 Jun 2021)");

  script_name("Debian: Security Advisory (DSA-4909-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4909-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4909-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4909");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/bind9");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-4909-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in BIND, a DNS server implementation.

CVE-2021-25214

Greg Kuechle discovered that a malformed incoming IXFR transfer could trigger an assertion failure in named, resulting in denial of service.

CVE-2021-25215

Siva Kakarla discovered that named could crash when a DNAME record placed in the ANSWER section during DNAME chasing turned out to be the final answer to a client query.

CVE-2021-25216

It was discovered that the SPNEGO implementation used by BIND is prone to a buffer overflow vulnerability. This update switches to use the SPNEGO implementation from the Kerberos libraries.

For the stable distribution (buster), these problems have been fixed in version 1:9.11.5.P4+dfsg-5.1+deb10u5.

We recommend that you upgrade your bind9 packages.

For the detailed security status of bind9 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind-export-dev", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind9-161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns-export1104", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns-export1104-udeb", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns1104", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libirs-export161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libirs-export161-udeb", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libirs161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc-export1100", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc-export1100-udeb", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc1100", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccc-export161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccc-export161-udeb", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccc161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg-export163", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg-export163-udeb", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg163", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblwres161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u5", rls:"DEB10"))) {
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
