# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6956.1");
  script_cve_id("CVE-2023-52585", "CVE-2023-52752", "CVE-2023-52882", "CVE-2024-25742", "CVE-2024-26886", "CVE-2024-26900", "CVE-2024-26936", "CVE-2024-26952", "CVE-2024-26980", "CVE-2024-27017", "CVE-2024-27398", "CVE-2024-27399", "CVE-2024-27401", "CVE-2024-35848", "CVE-2024-35947", "CVE-2024-36016", "CVE-2024-36017", "CVE-2024-36880", "CVE-2024-36883", "CVE-2024-36886", "CVE-2024-36889", "CVE-2024-36897", "CVE-2024-36902", "CVE-2024-36904", "CVE-2024-36905", "CVE-2024-36906", "CVE-2024-36916", "CVE-2024-36919", "CVE-2024-36928", "CVE-2024-36929", "CVE-2024-36931", "CVE-2024-36933", "CVE-2024-36934", "CVE-2024-36937", "CVE-2024-36938", "CVE-2024-36939", "CVE-2024-36940", "CVE-2024-36941", "CVE-2024-36944", "CVE-2024-36946", "CVE-2024-36947", "CVE-2024-36950", "CVE-2024-36952", "CVE-2024-36953", "CVE-2024-36954", "CVE-2024-36955", "CVE-2024-36957", "CVE-2024-36959", "CVE-2024-36960", "CVE-2024-36964", "CVE-2024-36965", "CVE-2024-36967", "CVE-2024-36969", "CVE-2024-36975", "CVE-2024-38600");
  script_tag(name:"creation_date", value:"2024-08-13 04:08:36 +0000 (Tue, 13 Aug 2024)");
  script_version("2024-08-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-08-13 05:05:46 +0000 (Tue, 13 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-23 19:14:05 +0000 (Thu, 23 May 2024)");

  script_name("Ubuntu: Security Advisory (USN-6956-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6956-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6956-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-5.15, linux-azure-fde, linux-azure-fde-5.15' package(s) announced via the USN-6956-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Benedict Schluter, Supraja Sridhara, Andrin Bertschi, and Shweta Shinde
discovered that an untrusted hypervisor could inject malicious #VC
interrupts and compromise the security guarantees of AMD SEV-SNP. This flaw
is known as WeSee. A local attacker in control of the hypervisor could use
this to expose sensitive information or possibly execute arbitrary code in
the trusted execution environment. (CVE-2024-25742)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM32 architecture,
 - ARM64 architecture,
 - Block layer subsystem,
 - Bluetooth drivers,
 - Clock framework and drivers,
 - FireWire subsystem,
 - GPU drivers,
 - InfiniBand drivers,
 - Multiple devices driver,
 - EEPROM drivers,
 - Network drivers,
 - Pin controllers subsystem,
 - Remote Processor subsystem,
 - S/390 drivers,
 - SCSI drivers,
 - TTY drivers,
 - 9P distributed file system,
 - Network file system client,
 - SMB network file system,
 - Socket messages infrastructure,
 - Dynamic debug library,
 - Bluetooth subsystem,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - Multipath TCP,
 - Netfilter,
 - NSH protocol,
 - Phonet protocol,
 - TIPC protocol,
 - Wireless networking,
 - Key management,
 - ALSA framework,
 - HD-audio driver,
(CVE-2024-36933, CVE-2024-36960, CVE-2024-26936, CVE-2024-36975,
CVE-2023-52882, CVE-2024-27401, CVE-2024-36929, CVE-2024-36939,
CVE-2024-35947, CVE-2024-36883, CVE-2024-26886, CVE-2024-36952,
CVE-2024-36950, CVE-2024-36940, CVE-2024-36897, CVE-2023-52585,
CVE-2024-26900, CVE-2024-36959, CVE-2024-36928, CVE-2024-36938,
CVE-2024-36016, CVE-2024-36965, CVE-2024-36967, CVE-2024-36889,
CVE-2024-36905, CVE-2024-36969, CVE-2024-36916, CVE-2024-36954,
CVE-2024-27017, CVE-2024-36941, CVE-2024-36957, CVE-2024-27399,
CVE-2024-36937, CVE-2024-36955, CVE-2024-38600, CVE-2023-52752,
CVE-2024-36953, CVE-2024-26980, CVE-2024-36902, CVE-2024-26952,
CVE-2024-36904, CVE-2024-36964, CVE-2024-36946, CVE-2024-36880,
CVE-2024-36906, CVE-2024-36947, CVE-2024-36886, CVE-2024-36934,
CVE-2024-35848, CVE-2024-36919, CVE-2024-36017, CVE-2024-36944,
CVE-2024-36931, CVE-2024-27398)");

  script_tag(name:"affected", value:"'linux-azure, linux-azure-5.15, linux-azure-fde, linux-azure-fde-5.15' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1070-azure", ver:"5.15.0-1070.79~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1070-azure-fde", ver:"5.15.0-1070.79~20.04.1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.15.0.1070.79~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-cvm", ver:"5.15.0.1070.79~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"5.15.0.1070.79~20.04.1.47", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1070-azure", ver:"5.15.0-1070.79", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1070-azure-fde", ver:"5.15.0-1070.79.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde-lts-22.04", ver:"5.15.0.1070.79.47", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-22.04", ver:"5.15.0.1070.68", rls:"UBUNTU22.04 LTS"))) {
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
