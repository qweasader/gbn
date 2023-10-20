# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841949");
  script_cve_id("CVE-2014-0155", "CVE-2014-0181", "CVE-2014-0206", "CVE-2014-4014", "CVE-2014-4027", "CVE-2014-4171", "CVE-2014-4508", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-5045");
  script_tag(name:"creation_date", value:"2014-09-03 03:55:32 +0000 (Wed, 03 Sep 2014)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2336-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2336-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2336-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-2336-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in the Linux kernel virtual machine's (kvm)
validation of interrupt requests (irq). A guest OS user could exploit this
flaw to cause a denial of service (host OS crash). (CVE-2014-0155)

Andy Lutomirski discovered a flaw in the authorization of netlink socket
operations when a socket is passed to a process of more privilege. A local
user could exploit this flaw to bypass access restrictions by having a
privileged executable do something it was not intended to do.
(CVE-2014-0181)

An information leak was discovered in the Linux kernels
aio_read_events_ring function. A local user could exploit this flaw to
obtain potentially sensitive information from kernel memory.
(CVE-2014-0206)

A flaw was discovered in the Linux kernel's implementation of user
namespaces with respect to inode permissions. A local user could exploit
this flaw by creating a user namespace to gain administrative privileges.
(CVE-2014-4014)

An information leak was discovered in the rd_mcp backend of the iSCSI
target subsystem in the Linux kernel. A local user could exploit this flaw
to obtain sensitive information from ramdisk_mcp memory by leveraging
access to a SCSI initiator. (CVE-2014-4027)

Sasha Levin reported an issue with the Linux kernel's shared memory
subsystem when used with range notifications and hole punching. A local
user could exploit this flaw to cause a denial of service. (CVE-2014-4171)

Toralf Forster reported an error in the Linux kernels syscall auditing on
32 bit x86 platforms. A local user could exploit this flaw to cause a
denial of service (OOPS and system crash). (CVE-2014-4508)

An information leak was discovered in the control implementation of the
Advanced Linux Sound Architecture (ALSA) subsystem in the Linux kernel. A
local user could exploit this flaw to obtain sensitive information from
kernel memory. (CVE-2014-4652)

A use-after-free flaw was discovered in the Advanced Linux Sound
Architecture (ALSA) control implementation of the Linux kernel. A local
user could exploit this flaw to cause a denial of service (system crash).
(CVE-2014-4653)

A authorization bug was discovered with the snd_ctl_elem_add function of
the Advanced Linux Sound Architecture (ALSA) in the Linux kernel. A local
user could exploit his bug to cause a denial of service (remove kernel
controls). (CVE-2014-4654)

A flaw discovered in how the snd_ctl_elem function of the Advanced Linux
Sound Architecture (ALSA) handled a reference count. A local user could
exploit this flaw to cause a denial of service (integer overflow and limit
bypass). (CVE-2014-4655)

An integer overflow flaw was discovered in the control implementation of
the Advanced Linux Sound Architecture (ALSA). A local user could exploit
this flaw to cause a denial of service (system crash). (CVE-2014-4656)

An integer underflow flaw was discovered in the Linux kernel's handling of
the backlog value for certain SCTP ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-lts-trusty' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-35-generic", ver:"3.13.0-35.62~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-35-generic-lpae", ver:"3.13.0-35.62~precise1", rls:"UBUNTU12.04 LTS"))) {
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
