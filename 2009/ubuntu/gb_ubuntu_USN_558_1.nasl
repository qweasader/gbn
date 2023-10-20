# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840180");
  script_cve_id("CVE-2006-6058", "CVE-2007-4133", "CVE-2007-4567", "CVE-2007-4849", "CVE-2007-4997", "CVE-2007-5093", "CVE-2007-5500", "CVE-2007-5501");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-558-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.10|7\.04|7\.10)");

  script_xref(name:"Advisory-ID", value:"USN-558-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-558-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/164231");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.17, linux-source-2.6.20, linux-source-2.6.22' package(s) announced via the USN-558-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The minix filesystem did not properly validate certain filesystem values.
If a local attacker could trick the system into attempting to mount a
corrupted minix filesystem, the kernel could be made to hang for long
periods of time, resulting in a denial of service. (CVE-2006-6058)

Certain calculations in the hugetlb code were not correct. A local
attacker could exploit this to cause a kernel panic, leading to a denial
of service. (CVE-2007-4133)

Eric Sesterhenn and Victor Julien discovered that the hop-by-hop IPv6
extended header was not correctly validated. If a system was configured
for IPv6, a remote attacker could send a specially crafted IPv6 packet
and cause the kernel to panic, leading to a denial of service. This
was only vulnerable in Ubuntu 7.04. (CVE-2007-4567)

Permissions were not correctly stored on JFFS2 ACLs. For systems using
ACLs on JFFS2, a local attacker may gain access to private files.
(CVE-2007-4849)

Chris Evans discovered that the 802.11 network stack did not correctly
handle certain QOS frames. A remote attacker on the local wireless network
could send specially crafted packets that would panic the kernel, resulting
in a denial of service. (CVE-2007-4997)

The Philips USB Webcam driver did not correctly handle disconnects.
If a local attacker tricked another user into disconnecting a webcam
unsafely, the kernel could hang or consume CPU resources, leading to
a denial of service. (CVE-2007-5093)

Scott James Remnant discovered that the waitid function could be made
to hang the system. A local attacker could execute a specially crafted
program which would leave the system unresponsive, resulting in a denial
of service. (CVE-2007-5500)

Ilpo Jarvinen discovered that it might be possible for the TCP stack
to panic the kernel when receiving a crafted ACK response. Only Ubuntu
7.10 contained the vulnerable code, and it is believed not to have
been exploitable. (CVE-2007-5501)

When mounting the same remote NFS share to separate local locations, the
first location's mount options would apply to all subsequent mounts of the
same NFS share. In some configurations, this could lead to incorrectly
configured permissions, allowing local users to gain additional access
to the mounted share. ([link moved to references])");

  script_tag(name:"affected", value:"'linux-source-2.6.17, linux-source-2.6.20, linux-source-2.6.22' package(s) on Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

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

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-386", ver:"2.6.17.1-12.42", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-generic", ver:"2.6.17.1-12.42", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-hppa32", ver:"2.6.17.1-12.42", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-hppa64", ver:"2.6.17.1-12.42", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-itanium", ver:"2.6.17.1-12.42", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-mckinley", ver:"2.6.17.1-12.42", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-powerpc", ver:"2.6.17.1-12.42", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-powerpc-smp", ver:"2.6.17.1-12.42", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-powerpc64-smp", ver:"2.6.17.1-12.42", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-server", ver:"2.6.17.1-12.42", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-server-bigiron", ver:"2.6.17.1-12.42", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-sparc64", ver:"2.6.17.1-12.42", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-sparc64-smp", ver:"2.6.17.1-12.42", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-386", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-generic", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-hppa32", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-hppa64", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-itanium", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-lowlatency", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-mckinley", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-powerpc", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-powerpc-smp", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-powerpc64-smp", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-server", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-server-bigiron", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-sparc64", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-sparc64-smp", ver:"2.6.20-16.33", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-386", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-cell", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-generic", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-hppa32", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-hppa64", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-itanium", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-lpia", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-lpiacompat", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-mckinley", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-powerpc", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-powerpc-smp", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-powerpc64-smp", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-rt", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-server", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-sparc64", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-sparc64-smp", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-ume", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-virtual", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-xen", ver:"2.6.22-14.47", rls:"UBUNTU7.10"))) {
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
