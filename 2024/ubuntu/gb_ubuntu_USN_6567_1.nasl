# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6567.1");
  script_cve_id("CVE-2020-14394", "CVE-2020-24165", "CVE-2021-3611", "CVE-2021-3638", "CVE-2023-1544", "CVE-2023-2861", "CVE-2023-3180", "CVE-2023-3255", "CVE-2023-3301", "CVE-2023-3354", "CVE-2023-40360", "CVE-2023-4135", "CVE-2023-42467", "CVE-2023-5088");
  script_tag(name:"creation_date", value:"2024-01-09 04:08:55 +0000 (Tue, 09 Jan 2024)");
  script_version("2024-01-09T05:06:46+0000");
  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-01 15:06:00 +0000 (Fri, 01 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6567-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6567-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6567-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-6567-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gaoning Pan and Xingwei Li discovered that QEMU incorrectly handled the
USB xHCI controller device. A privileged guest attacker could possibly use
this issue to cause QEMU to crash, leading to a denial of service. This
issue only affected Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2020-14394)

It was discovered that QEMU incorrectly handled the TCG Accelerator. A
local attacker could use this issue to cause QEMU to crash, leading to a
denial of service, or possibly execute arbitrary code and esclate
privileges. This issue only affected Ubuntu 20.04 LTS. (CVE-2020-24165)

It was discovered that QEMU incorrectly handled the Intel HD audio device.
A malicious guest attacker could use this issue to cause QEMU to crash,
leading to a denial of service. This issue only affected Ubuntu 22.04 LTS.
(CVE-2021-3611)

It was discovered that QEMU incorrectly handled the ATI VGA device. A
malicious guest attacker could use this issue to cause QEMU to crash,
leading to a denial of service. This issue only affected Ubuntu 20.04 LTS.
(CVE-2021-3638)

It was discovered that QEMU incorrectly handled the VMWare paravirtual RDMA
device. A malicious guest attacker could use this issue to cause QEMU to
crash, leading to a denial of service. (CVE-2023-1544)

It was discovered that QEMU incorrectly handled the 9p passthrough
filesystem. A malicious guest attacker could possibly use this issue to
open special files and escape the exported 9p tree. This issue only
affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, and Ubuntu 23.04.
(CVE-2023-2861)

It was discovered that QEMU incorrectly handled the virtual crypto device.
A malicious guest attacker could use this issue to cause QEMU to crash,
leading to a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, and Ubuntu 23.04.
(CVE-2023-3180)

It was discovered that QEMU incorrectly handled the built-in VNC server.
A remote authenticated attacker could possibly use this issue to cause QEMU
to stop responding, resulting in a denial of service. This issue only
affected Ubuntu 22.04 LTS and Ubuntu 23.04. (CVE-2023-3255)

It was discovered that QEMU incorrectly handled net device hot-unplugging.
A malicious guest attacker could use this issue to cause QEMU to crash,
leading to a denial of service. This issue only affected Ubuntu 22.04 LTS
and Ubuntu 23.04. (CVE-2023-3301)

It was discovered that QEMU incorrectly handled the built-in VNC server.
A remote attacker could possibly use this issue to cause QEMU to crash,
resulting in a denial of service. This issue only affected Ubuntu 20.04
LTS, Ubuntu 22.04 LTS, and Ubuntu 23.04. (CVE-2023-3354)

It was discovered that QEMU incorrectly handled NVME devices. A malicious
guest attacker could use this issue to cause QEMU to crash, leading to a
denial of service. This issue only affected Ubuntu 23.10. (CVE-2023-40360)

It was discovered that QEMU ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04, Ubuntu 23.10.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:4.2-3ubuntu6.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:4.2-3ubuntu6.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:4.2-3ubuntu6.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:4.2-3ubuntu6.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:4.2-3ubuntu6.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:4.2-3ubuntu6.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:4.2-3ubuntu6.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:4.2-3ubuntu6.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:4.2-3ubuntu6.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-microvm", ver:"1:4.2-3ubuntu6.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:4.2-3ubuntu6.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:6.2+dfsg-2ubuntu6.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:6.2+dfsg-2ubuntu6.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:6.2+dfsg-2ubuntu6.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:6.2+dfsg-2ubuntu6.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:6.2+dfsg-2ubuntu6.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:6.2+dfsg-2ubuntu6.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:6.2+dfsg-2ubuntu6.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:6.2+dfsg-2ubuntu6.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-microvm", ver:"1:6.2+dfsg-2ubuntu6.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:6.2+dfsg-2ubuntu6.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:7.2+dfsg-5ubuntu2.4", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:7.2+dfsg-5ubuntu2.4", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:7.2+dfsg-5ubuntu2.4", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:7.2+dfsg-5ubuntu2.4", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:7.2+dfsg-5ubuntu2.4", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:7.2+dfsg-5ubuntu2.4", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:7.2+dfsg-5ubuntu2.4", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:7.2+dfsg-5ubuntu2.4", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:7.2+dfsg-5ubuntu2.4", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-xen", ver:"1:7.2+dfsg-5ubuntu2.4", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:8.0.4+dfsg-1ubuntu3.23.10.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:8.0.4+dfsg-1ubuntu3.23.10.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:8.0.4+dfsg-1ubuntu3.23.10.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:8.0.4+dfsg-1ubuntu3.23.10.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:8.0.4+dfsg-1ubuntu3.23.10.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:8.0.4+dfsg-1ubuntu3.23.10.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:8.0.4+dfsg-1ubuntu3.23.10.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:8.0.4+dfsg-1ubuntu3.23.10.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:8.0.4+dfsg-1ubuntu3.23.10.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-xen", ver:"1:8.0.4+dfsg-1ubuntu3.23.10.2", rls:"UBUNTU23.10"))) {
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
