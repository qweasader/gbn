# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3498");
  script_cve_id("CVE-2023-2828");
  script_tag(name:"creation_date", value:"2023-07-20 04:30:53 +0000 (Thu, 20 Jul 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-21 17:15:47 +0000 (Wed, 21 Jun 2023)");

  script_name("Debian: Security Advisory (DLA-3498-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3498-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3498-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DLA-3498-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential denial of service (DoS) in bind9, the popular Domain Name Server (DNS) server. Shoham Danino, Anat Bremler-Barr, Yehuda Afek and Yuval Shavitt discovered that a flaw in the cache-cleaning algorithm used in named can cause that named's configured cache size limit can be significantly exceeded, potentially resulting in a denial of service attack.

CVE-2023-2828

For Debian 10 Buster, this problem has been fixed in version 1:9.11.5.P4+dfsg-5.1+deb10u9.

We recommend that you upgrade your bind9 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind-export-dev", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind9-161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns-export1104", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns-export1104-udeb", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns1104", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libirs-export161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libirs-export161-udeb", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libirs161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc-export1100", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc-export1100-udeb", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc1100", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccc-export161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccc-export161-udeb", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccc161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg-export163", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg-export163-udeb", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg163", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblwres161", ver:"1:9.11.5.P4+dfsg-5.1+deb10u9", rls:"DEB10"))) {
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
