# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703286");
  script_cve_id("CVE-2015-3209", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106", "CVE-2015-4163", "CVE-2015-4164");
  script_tag(name:"creation_date", value:"2015-06-12 22:00:00 +0000 (Fri, 12 Jun 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-3286-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3286-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3286-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3286");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-3286-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Xen virtualisation solution:

CVE-2015-3209

Matt Tait discovered a flaw in the way QEMU's AMD PCnet Ethernet emulation handles multi-TMD packets with a length above 4096 bytes. A privileged guest user in a guest with an AMD PCNet ethernet card enabled can potentially use this flaw to execute arbitrary code on the host with the privileges of the hosting QEMU process.

CVE-2015-4103

Jan Beulich discovered that the QEMU Xen code does not properly restrict write access to the host MSI message data field, allowing a malicious guest to cause a denial of service.

CVE-2015-4104

Jan Beulich discovered that the QEMU Xen code does not properly restrict access to PCI MSI mask bits, allowing a malicious guest to cause a denial of service.

CVE-2015-4105

Jan Beulich reported that the QEMU Xen code enables logging for PCI MSI-X pass-through error messages, allowing a malicious guest to cause a denial of service.

CVE-2015-4106

Jan Beulich discovered that the QEMU Xen code does not properly restrict write access to the PCI config space for certain PCI pass-through devices, allowing a malicious guest to cause a denial of service, obtain sensitive information or potentially execute arbitrary code.

CVE-2015-4163

Jan Beulich discovered that a missing version check in the GNTTABOP_swap_grant_ref hypercall handler may result in denial of service. This only applies to Debian stable/jessie.

CVE-2015-4164

Andrew Cooper discovered a vulnerability in the iret hypercall handler, which may result in denial of service.

For the oldstable distribution (wheezy), these problems have been fixed in version 4.1.4-3+deb7u8.

For the stable distribution (jessie), these problems have been fixed in version 4.4.1-9+deb8u1. CVE-2015-3209, CVE-2015-4103, CVE-2015-4104, CVE-2015-4105 and CVE-2015-4106 don't affect the Xen package in stable jessie, it uses the standard qemu package and has already been fixed in DSA-3284-1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxen-4.1", ver:"4.1.4-3+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.1.4-3+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-ocaml", ver:"4.1.4-3+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-ocaml-dev", ver:"4.1.4-3+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.1.4-3+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-docs-4.1", ver:"4.1.4-3+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.1-amd64", ver:"4.1.4-3+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.1-i386", ver:"4.1.4-3+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.1.4-3+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-i386", ver:"4.1.4-3+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.1", ver:"4.1.4-3+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.1.4-3+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.1.4-3+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libxen-4.4", ver:"4.4.1-9+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.4.1-9+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.4.1-9+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.4-amd64", ver:"4.4.1-9+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.4-arm64", ver:"4.4.1-9+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.4-armhf", ver:"4.4.1-9+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.4.1-9+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.4.1-9+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.4.1-9+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.4", ver:"4.4.1-9+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.4.1-9+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.4.1-9+deb8u1", rls:"DEB8"))) {
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
