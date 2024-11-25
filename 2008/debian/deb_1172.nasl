# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57357");
  script_cve_id("CVE-2006-4095", "CVE-2006-4096");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 21:04:44 +0000 (Thu, 15 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1172-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1172-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1172-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1172");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-1172-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in BIND9, the Berkeley Internet Name Domain server. The first relates to SIG query processing and the second relates to a condition that can trigger an INSIST failure, both lead to a denial of service.

For the stable distribution (sarge) these problems have been fixed in version 9.2.4-1sarge1.

For the unstable distribution (sid) these problems have been fixed in version 9.3.2-P1-1.

We recommend that you upgrade your bind9 package.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.2.4-1sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.2.4-1sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.2.4-1sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.2.4-1sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.2.4-1sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns16", ver:"1:9.2.4-1sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc7", ver:"1:9.2.4-1sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccc0", ver:"1:9.2.4-1sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg0", ver:"1:9.2.4-1sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblwres1", ver:"1:9.2.4-1sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lwresd", ver:"1:9.2.4-1sarge1", rls:"DEB3.1"))) {
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
