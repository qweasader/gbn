# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841430");
  script_cve_id("CVE-2012-6549", "CVE-2013-1826", "CVE-2013-1860", "CVE-2013-1928", "CVE-2013-2634");
  script_tag(name:"creation_date", value:"2013-05-17 04:25:56 +0000 (Fri, 17 May 2013)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1824-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1824-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1824-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1824-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mathias Krause discovered an information leak in the Linux kernel's ISO
9660 CDROM file system driver. A local user could exploit this flaw to
examine some of the kernel's heap memory. (CVE-2012-6549)

Mathias Krause discovered a flaw in xfrm_user in the Linux kernel. A local
attacker with NET_ADMIN capability could potentially exploit this flaw to
escalate privileges. (CVE-2013-1826)

A buffer overflow was discovered in the Linux Kernel's USB subsystem for
devices reporting the cdc-wdm class. A specially crafted USB device when
plugged-in could cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2013-1860)

An information leak was discovered in the Linux kernel's /dev/dvb device. A
local user could exploit this flaw to obtain sensitive information from the
kernel's stack memory. (CVE-2013-1928)

An information leak in the Linux kernel's dcb netlink interface was
discovered. A local user could obtain sensitive information by examining
kernel stack memory. (CVE-2013-2634)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-386", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-generic", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-generic-pae", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-ia64", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-lpia", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-powerpc", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-powerpc-smp", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-powerpc64-smp", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-preempt", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-server", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-sparc64", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-sparc64-smp", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-versatile", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-47-virtual", ver:"2.6.32-47.109", rls:"UBUNTU10.04 LTS"))) {
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
