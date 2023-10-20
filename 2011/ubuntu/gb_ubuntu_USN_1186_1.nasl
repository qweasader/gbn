# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840720");
  script_cve_id("CVE-2010-4073", "CVE-2010-4165", "CVE-2010-4238", "CVE-2010-4249", "CVE-2010-4649", "CVE-2011-0711", "CVE-2011-1010", "CVE-2011-1044", "CVE-2011-1090", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-2484", "CVE-2011-2534");
  script_tag(name:"creation_date", value:"2011-08-12 13:49:01 +0000 (Fri, 12 Aug 2011)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 20:03:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-1186-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU8\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1186-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1186-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1186-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that IPC structures were not correctly initialized
on 64bit systems. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2010-4073)

Steve Chen discovered that setsockopt did not correctly check MSS values. A
local attacker could make a specially crafted socket call to crash the
system, leading to a denial of service. (CVE-2010-4165)

Vladymyr Denysov discovered that Xen virtual CD-ROM devices were not
handled correctly. A local attacker in a guest could make crafted blkback
requests that would crash the host, leading to a denial of service.
(CVE-2010-4238)

Vegard Nossum discovered that memory garbage collection was not handled
correctly for active sockets. A local attacker could exploit this to
allocate all available kernel memory, leading to a denial of service.
(CVE-2010-4249)

Dan Carpenter discovered that the Infiniband driver did not correctly
handle certain requests. A local user could exploit this to crash the
system or potentially gain root privileges. (CVE-2010-4649, CVE-2011-1044)

Dan Rosenberg discovered that XFS did not correctly initialize memory. A
local attacker could make crafted ioctl calls to leak portions of kernel
stack memory, leading to a loss of privacy. (CVE-2011-0711)

Timo Warns discovered that MAC partition parsing routines did not correctly
calculate block counts. A local attacker with physical access could plug in
a specially crafted block device to crash the system or potentially gain
root privileges. (CVE-2011-1010)

Neil Horman discovered that NFSv4 did not correctly handle certain orders
of operation with ACL data. A remote attacker with access to an NFSv4 mount
could exploit this to crash the system, leading to a denial of service.
(CVE-2011-1090)

Vasiliy Kulikov discovered that the netfilter code did not check certain
strings copied from userspace. A local attacker with netfilter access could
exploit this to read kernel memory or crash the system, leading to a denial
of service. (CVE-2011-1170, CVE-2011-1171, CVE-2011-1172, CVE-2011-2534)

Vasiliy Kulikov discovered that the Acorn Universal Networking driver did
not correctly initialize memory. A remote attacker could send specially
crafted traffic to read kernel stack memory, leading to a loss of privacy.
(CVE-2011-1173)

Vasiliy Kulikov discovered that taskstats listeners were not correctly
handled. A local attacker could exploit this to exhaust memory and CPU
resources, leading to a denial of service. (CVE-2011-2484)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 8.04.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-386", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-generic", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-hppa32", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-hppa64", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-itanium", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-lpia", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-lpiacompat", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-mckinley", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-openvz", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-powerpc", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-powerpc-smp", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-powerpc64-smp", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-rt", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-server", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-sparc64", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-sparc64-smp", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-virtual", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-29-xen", ver:"2.6.24-29.92", rls:"UBUNTU8.04 LTS"))) {
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
