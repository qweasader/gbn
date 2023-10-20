# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844234");
  script_cve_id("CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-11135", "CVE-2019-15098", "CVE-2019-17052", "CVE-2019-17053", "CVE-2019-17054");
  script_tag(name:"creation_date", value:"2019-11-14 03:01:20 +0000 (Thu, 14 Nov 2019)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-30 11:15:00 +0000 (Thu, 30 Jan 2020)");

  script_name("Ubuntu: Security Advisory (USN-4185-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4185-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4185-3");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/bugs/1851709");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/bugs/1852141");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-hwe, linux-oem' package(s) announced via the USN-4185-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4185-1 fixed vulnerabilities in the Linux kernel. It was discovered
that the kernel fix for CVE-2019-0155 (i915 missing Blitter Command
Streamer check) was incomplete on 64-bit Intel x86 systems. Also, the
update introduced a regression that broke KVM guests where extended
page tables (EPT) are disabled or not supported. This update addresses
both issues.

We apologize for the inconvenience.

Original advisory details:

 Stephan van Schaik, Alyssa Milburn, Sebastian Osterlund, Pietro Frigo,
 Kaveh Razavi, Herbert Bos, Cristiano Giuffrida, Giorgi Maisuradze, Moritz
 Lipp, Michael Schwarz, Daniel Gruss, and Jo Van Bulck discovered that Intel
 processors using Transactional Synchronization Extensions (TSX) could
 expose memory contents previously stored in microarchitectural buffers to a
 malicious process that is executing on the same CPU core. A local attacker
 could use this to expose sensitive information. (CVE-2019-11135)

 It was discovered that the Intel i915 graphics chipsets allowed userspace
 to modify page table entries via writes to MMIO from the Blitter Command
 Streamer and expose kernel memory information. A local attacker could use
 this to expose sensitive information or possibly elevate privileges.
 (CVE-2019-0155)

 Deepak Gupta discovered that on certain Intel processors, the Linux kernel
 did not properly perform invalidation on page table updates by virtual
 guest operating systems. A local attacker in a guest VM could use this to
 cause a denial of service (host system crash). (CVE-2018-12207)

 It was discovered that the Intel i915 graphics chipsets could cause a
 system hang when userspace performed a read from GT memory mapped input
 output (MMIO) when the product is in certain low power states. A local
 attacker could use this to cause a denial of service. (CVE-2019-0154)

 Hui Peng discovered that the Atheros AR6004 USB Wi-Fi device driver for the
 Linux kernel did not properly validate endpoint descriptors returned by the
 device. A physically proximate attacker could use this to cause a denial of
 service (system crash). (CVE-2019-15098)

 Ori Nimron discovered that the AX25 network protocol implementation in the
 Linux kernel did not properly perform permissions checks. A local attacker
 could use this to create a raw socket. (CVE-2019-17052)

 Ori Nimron discovered that the IEEE 802.15.4 Low-Rate Wireless network
 protocol implementation in the Linux kernel did not properly perform
 permissions checks. A local attacker could use this to create a raw socket.
 (CVE-2019-17053)

 Ori Nimron discovered that the Appletalk network protocol implementation in
 the Linux kernel did not properly perform permissions checks. A local
 attacker could use this to create a raw socket. (CVE-2019-17054)

 Ori Nimron discovered that the modular ISDN network protocol implementation
 in the Linux kernel did not properly perform permissions checks. A local
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-hwe, linux-oem' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-70-generic", ver:"4.15.0-70.79~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-70-generic-lpae", ver:"4.15.0-70.79~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-70-lowlatency", ver:"4.15.0-70.79~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.15.0.70.90", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-16.04", ver:"4.15.0.70.90", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.15.0.70.90", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.15.0.70.90", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-16.04", ver:"4.15.0.70.90", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1064-oem", ver:"4.15.0-1064.73", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-70-generic", ver:"4.15.0-70.79", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-70-generic-lpae", ver:"4.15.0-70.79", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-70-lowlatency", ver:"4.15.0-70.79", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.15.0.70.72", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.15.0.70.72", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.15.0.70.72", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.15.0.1064.68", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.15.0.70.72", rls:"UBUNTU18.04 LTS"))) {
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
