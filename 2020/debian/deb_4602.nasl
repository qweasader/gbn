# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704602");
  script_cve_id("CVE-2018-12207", "CVE-2019-11135", "CVE-2019-17349", "CVE-2019-17350", "CVE-2019-18420", "CVE-2019-18421", "CVE-2019-18422", "CVE-2019-18423", "CVE-2019-18424", "CVE-2019-18425", "CVE-2019-19577", "CVE-2019-19578", "CVE-2019-19579", "CVE-2019-19580", "CVE-2019-19581", "CVE-2019-19582", "CVE-2019-19583");
  script_tag(name:"creation_date", value:"2020-01-14 04:00:38 +0000 (Tue, 14 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-14 16:15:00 +0000 (Thu, 14 Nov 2019)");

  script_name("Debian: Security Advisory (DSA-4602)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4602");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4602");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4602");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-305.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xen");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-4602 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor, which could result in denial of service, guest-to-host privilege escalation or information leaks.

In addition this update provides mitigations for the TSX Asynchronous Abort speculative side channel attack. For additional information please refer to [link moved to references]

For the oldstable distribution (stretch), these problems have been fixed in version 4.8.5.final+shim4.10.4-1+deb9u12. Note that this will be the last security update for Xen in the oldstable distribution, upstream support for the 4.8.x branch ended by the end of December 2019. If you rely on security support for your Xen installation an update to the stable distribution (buster) is recommended.

For the stable distribution (buster), these problems have been fixed in version 4.11.3+24-g14b62ab3e5-1~deb10u1.

We recommend that you upgrade your xen packages.

For the detailed security status of xen please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 9, Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxencall1", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxendevicemodel1", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenevtchn1", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenforeignmemory1", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxengnttab1", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenmisc4.11", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxentoolcore1", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxentoollog1", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-doc", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.11-amd64", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.11-arm64", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.11-armhf", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-common", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.11", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.11.3+24-g14b62ab3e5-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libxen-4.8", ver:"4.8.5.final+shim4.10.4-1+deb9u12", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.8.5.final+shim4.10.4-1+deb9u12", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.8.5.final+shim4.10.4-1+deb9u12", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.8-amd64", ver:"4.8.5.final+shim4.10.4-1+deb9u12", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.8-arm64", ver:"4.8.5.final+shim4.10.4-1+deb9u12", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.8-armhf", ver:"4.8.5.final+shim4.10.4-1+deb9u12", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.8.5.final+shim4.10.4-1+deb9u12", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.8.5.final+shim4.10.4-1+deb9u12", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.8.5.final+shim4.10.4-1+deb9u12", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.8", ver:"4.8.5.final+shim4.10.4-1+deb9u12", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.8.5.final+shim4.10.4-1+deb9u12", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.8.5.final+shim4.10.4-1+deb9u12", rls:"DEB9"))) {
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
