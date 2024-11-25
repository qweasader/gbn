# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845063");
  script_cve_id("CVE-2020-36311", "CVE-2021-22543", "CVE-2021-3612", "CVE-2021-3653", "CVE-2021-3656");
  script_tag(name:"creation_date", value:"2021-09-17 01:00:26 +0000 (Fri, 17 Sep 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 18:55:35 +0000 (Thu, 10 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5071-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5071-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5071-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-hwe-5.4' package(s) announced via the USN-5071-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5071-1 fixed vulnerabilities in the Linux kernel for Ubuntu 20.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 20.04 LTS for Ubuntu
18.04 LTS.

Maxim Levitsky and Paolo Bonzini discovered that the KVM hypervisor
implementation for AMD processors in the Linux kernel allowed a guest VM to
disable restrictions on VMLOAD/VMSAVE in a nested guest. An attacker in a
guest VM could use this to read or write portions of the host's physical
memory. (CVE-2021-3656)

Maxim Levitsky discovered that the KVM hypervisor implementation for AMD
processors in the Linux kernel did not properly prevent a guest VM from
enabling AVIC in nested guest VMs. An attacker in a guest VM could use this
to write to portions of the host's physical memory. (CVE-2021-3653)

It was discovered that the KVM hypervisor implementation for AMD processors
in the Linux kernel did not ensure enough processing time was given to
perform cleanups of large SEV VMs. A local attacker could use this to cause
a denial of service (soft lockup). (CVE-2020-36311)

It was discovered that the KVM hypervisor implementation in the Linux
kernel did not properly perform reference counting in some situations,
leading to a use-after-free vulnerability. An attacker who could start and
control a VM could possibly use this to expose sensitive information or
execute arbitrary code. (CVE-2021-22543)

Murray McAllister discovered that the joystick device interface in the
Linux kernel did not properly validate data passed via an ioctl(). A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code on systems with a joystick device
registered. (CVE-2021-3612)");

  script_tag(name:"affected", value:"'linux-hwe-5.4' package(s) on Ubuntu 18.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-84-generic", ver:"5.4.0-84.94~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-84-generic-lpae", ver:"5.4.0-84.94~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-84-lowlatency", ver:"5.4.0-84.94~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-18.04", ver:"5.4.0.84.94~18.04.75", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-18.04", ver:"5.4.0.84.94~18.04.75", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-18.04", ver:"5.4.0.84.94~18.04.75", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"5.4.0.84.94~18.04.75", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-osp1", ver:"5.4.0.84.94~18.04.75", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon-hwe-18.04", ver:"5.4.0.84.94~18.04.75", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-18.04", ver:"5.4.0.84.94~18.04.75", rls:"UBUNTU18.04 LTS"))) {
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
