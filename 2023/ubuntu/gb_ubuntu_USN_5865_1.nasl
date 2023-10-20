# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5865.1");
  script_cve_id("CVE-2022-20369", "CVE-2022-26373", "CVE-2022-2663", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-3646", "CVE-2022-3649", "CVE-2022-39842", "CVE-2022-41849", "CVE-2022-41850", "CVE-2022-43750");
  script_tag(name:"creation_date", value:"2023-02-13 04:10:52 +0000 (Mon, 13 Feb 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-01 18:51:00 +0000 (Wed, 01 Feb 2023)");

  script_name("Ubuntu: Security Advisory (USN-5865-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5865-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5865-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure-4.15' package(s) announced via the USN-5865-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that an out-of-bounds write vulnerability existed in the
Video for Linux 2 (V4L2) implementation in the Linux kernel. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2022-20369)

Pawan Kumar Gupta, Alyssa Milburn, Amit Peled, Shani Rehana, Nir Shildan
and Ariel Sabba discovered that some Intel processors with Enhanced
Indirect Branch Restricted Speculation (eIBRS) did not properly handle RET
instructions after a VM exits. A local attacker could potentially use this
to expose sensitive information. (CVE-2022-26373)

David Leadbeater discovered that the netfilter IRC protocol tracking
implementation in the Linux Kernel incorrectly handled certain message
payloads in some situations. A remote attacker could possibly use this to
cause a denial of service or bypass firewall filtering. (CVE-2022-2663)

Johannes Wikner and Kaveh Razavi discovered that for some AMD x86-64
processors, the branch predictor could by mis-trained for return
instructions in certain circumstances. A local attacker could possibly use
this to expose sensitive information. (CVE-2022-29900)

Johannes Wikner and Kaveh Razavi discovered that for some Intel x86-64
processors, the Linux kernel's protections against speculative branch
target injection attacks were insufficient in some circumstances. A local
attacker could possibly use this to expose sensitive information.
(CVE-2022-29901)

It was discovered that the NILFS2 file system implementation in the Linux
kernel did not properly deallocate memory in certain error conditions. An
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2022-3646)

Khalid Masum discovered that the NILFS2 file system implementation in the
Linux kernel did not properly handle certain error conditions, leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service or possibly execute arbitrary code. (CVE-2022-3649)

Hyunwoo Kim discovered that an integer overflow vulnerability existed in
the PXA3xx graphics driver in the Linux kernel. A local attacker could
possibly use this to cause a denial of service (system crash).
(CVE-2022-39842)

It was discovered that a race condition existed in the SMSC UFX USB driver
implementation in the Linux kernel, leading to a use-after-free
vulnerability. A physically proximate attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2022-41849)

It was discovered that a race condition existed in the Roccat HID driver in
the Linux kernel, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2022-41850)

It was discovered that the USB monitoring (usbmon) component in the Linux
kernel did not properly set permissions on memory mapped in to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-azure-4.15' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1161-azure", ver:"4.15.0-1161.176", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-18.04", ver:"4.15.0.1161.129", rls:"UBUNTU18.04 LTS"))) {
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
