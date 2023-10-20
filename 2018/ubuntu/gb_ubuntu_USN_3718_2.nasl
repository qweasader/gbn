# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843596");
  script_cve_id("CVE-2018-1094", "CVE-2018-10940", "CVE-2018-1095", "CVE-2018-1108", "CVE-2018-11508", "CVE-2018-7755");
  script_tag(name:"creation_date", value:"2018-07-24 04:00:16 +0000 (Tue, 24 Jul 2018)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-04 18:15:00 +0000 (Fri, 04 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-3718-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3718-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3718-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1779827");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/usn/usn-3695-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-gcp, linux-hwe' package(s) announced via the USN-3718-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3695-2 fixed vulnerabilities in the Linux Hardware Enablement
Kernel (HWE) kernel for Ubuntu 16.04 LTS. Unfortunately, the fix
for CVE-2018-1108 introduced a regression where insufficient early
entropy prevented services from starting, leading in some situations
to a failure to boot, This update addresses the issue.

We apologize for the inconvenience.

Original advisory details:

 Jann Horn discovered that the Linux kernel's implementation of random
 seed data reported that it was in a ready state before it had gathered
 sufficient entropy. An attacker could use this to expose sensitive
 information. (CVE-2018-1108)

 Wen Xu discovered that the ext4 file system implementation in the Linux
 kernel did not properly initialize the crc32c checksum driver. A local
 attacker could use this to cause a denial of service (system crash).
 (CVE-2018-1094)

 It was discovered that the cdrom driver in the Linux kernel contained an
 incorrect bounds check. A local attacker could use this to expose sensitive
 information (kernel memory). (CVE-2018-10940)

 Wen Xu discovered that the ext4 file system implementation in the Linux
 kernel did not properly validate xattr sizes. A local attacker could use
 this to cause a denial of service (system crash). (CVE-2018-1095)

 Jann Horn discovered that the 32 bit adjtimex() syscall implementation for
 64 bit Linux kernels did not properly initialize memory returned to user
 space in some situations. A local attacker could use this to expose
 sensitive information (kernel memory). (CVE-2018-11508)

 It was discovered that an information leak vulnerability existed in the
 floppy driver in the Linux kernel. A local attacker could use this to
 expose sensitive information (kernel memory). (CVE-2018-7755)");

  script_tag(name:"affected", value:"'linux-azure, linux-gcp, linux-hwe' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1014-gcp", ver:"4.15.0-1014.14~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1018-azure", ver:"4.15.0-1018.18~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-29-generic", ver:"4.15.0-29.31~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-29-generic-lpae", ver:"4.15.0-29.31~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-29-lowlatency", ver:"4.15.0-29.31~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1018.24", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1014.26", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.13.0.45.64", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-16.04", ver:"4.13.0.45.64", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1014.26", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.13.0.45.64", rls:"UBUNTU16.04 LTS"))) {
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
