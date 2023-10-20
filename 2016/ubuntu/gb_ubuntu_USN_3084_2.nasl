# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842888");
  script_cve_id("CVE-2016-5412", "CVE-2016-6136", "CVE-2016-6156");
  script_tag(name:"creation_date", value:"2016-09-20 03:41:44 +0000 (Tue, 20 Sep 2016)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-3084-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3084-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3084-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-xenial' package(s) announced via the USN-3084-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3084-1 fixed vulnerabilities in the Linux kernel for Ubuntu
16.04 LTS. This update provides the corresponding updates for the
Linux Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for
Ubuntu 14.04 LTS.

Pengfei Wang discovered a race condition in the audit subsystem in the
Linux kernel. A local attacker could use this to corrupt audit logs or
disrupt system-call auditing. (CVE-2016-6136)

It was discovered that the powerpc and powerpc64 hypervisor-mode KVM
implementation in the Linux kernel for did not properly maintain state
about transactional memory. An unprivileged attacker in a guest could cause
a denial of service (CPU lockup) in the host OS. (CVE-2016-5412)

Pengfei Wang discovered a race condition in the Chrome OS embedded
controller device driver in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash). (CVE-2016-6156)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-38-generic", ver:"4.4.0-38.57~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-38-generic-lpae", ver:"4.4.0-38.57~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-38-lowlatency", ver:"4.4.0-38.57~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-38-powerpc-e500mc", ver:"4.4.0-38.57~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-38-powerpc-smp", ver:"4.4.0-38.57~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-38-powerpc64-emb", ver:"4.4.0-38.57~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-38-powerpc64-smp", ver:"4.4.0-38.57~14.04.1", rls:"UBUNTU14.04 LTS"))) {
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
