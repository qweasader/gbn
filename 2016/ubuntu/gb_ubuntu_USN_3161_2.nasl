# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843004");
  script_cve_id("CVE-2015-8964", "CVE-2016-4568", "CVE-2016-6213", "CVE-2016-8630", "CVE-2016-8633", "CVE-2016-8645", "CVE-2016-9555");
  script_tag(name:"creation_date", value:"2016-12-21 04:45:50 +0000 (Wed, 21 Dec 2016)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 16:13:00 +0000 (Thu, 19 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-3161-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3161-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3161-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-xenial' package(s) announced via the USN-3161-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3161-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 LTS.

Tilman Schmidt and Sasha Levin discovered a use-after-free condition in the
TTY implementation in the Linux kernel. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2015-8964)

It was discovered that the Video For Linux Two (v4l2) implementation in the
Linux kernel did not properly handle multiple planes when processing a
VIDIOC_DQBUF ioctl(). A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2016-4568)

CAI Qian discovered that shared bind mounts in a mount namespace
exponentially added entries without restriction to the Linux kernel's mount
table. A local attacker could use this to cause a denial of service (system
crash). (CVE-2016-6213)

It was discovered that the KVM implementation for x86/x86_64 in the Linux
kernel could dereference a null pointer. An attacker in a guest virtual
machine could use this to cause a denial of service (system crash) in the
KVM host. (CVE-2016-8630)

Eyal Itkin discovered that the IP over IEEE 1394 (FireWire) implementation
in the Linux kernel contained a buffer overflow when handling fragmented
packets. A remote attacker could use this to possibly execute arbitrary
code with administrative privileges. (CVE-2016-8633)

Marco Grassi discovered that the TCP implementation in the Linux kernel
mishandles socket buffer (skb) truncation. A local attacker could use this
to cause a denial of service (system crash). (CVE-2016-8645)

Andrey Konovalov discovered that the SCTP implementation in the Linux
kernel improperly handled validation of incoming data. A remote attacker
could use this to cause a denial of service (system crash). (CVE-2016-9555)");

  script_tag(name:"affected", value:"'linux-lts-xenial' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-57-generic", ver:"4.4.0-57.78~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-57-generic-lpae", ver:"4.4.0-57.78~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-57-lowlatency", ver:"4.4.0-57.78~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-57-powerpc-e500mc", ver:"4.4.0-57.78~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-57-powerpc-smp", ver:"4.4.0-57.78~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-57-powerpc64-emb", ver:"4.4.0-57.78~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-57-powerpc64-smp", ver:"4.4.0-57.78~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-xenial", ver:"4.4.0.57.44", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.57.44", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.57.44", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc-lts-xenial", ver:"4.4.0.57.44", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp-lts-xenial", ver:"4.4.0.57.44", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-emb-lts-xenial", ver:"4.4.0.57.44", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp-lts-xenial", ver:"4.4.0.57.44", rls:"UBUNTU14.04 LTS"))) {
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
