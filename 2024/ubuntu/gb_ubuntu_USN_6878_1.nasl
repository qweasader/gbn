# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6878.1");
  script_cve_id("CVE-2022-38096", "CVE-2022-48669", "CVE-2023-47233", "CVE-2023-52644", "CVE-2023-52647", "CVE-2023-52648", "CVE-2023-52649", "CVE-2023-52650", "CVE-2023-52652", "CVE-2023-52653", "CVE-2023-52659", "CVE-2023-52661", "CVE-2023-52662", "CVE-2023-52663", "CVE-2023-6270", "CVE-2023-7042", "CVE-2024-21823", "CVE-2024-23307", "CVE-2024-24861", "CVE-2024-25739", "CVE-2024-26651", "CVE-2024-26653", "CVE-2024-26654", "CVE-2024-26655", "CVE-2024-26656", "CVE-2024-26657", "CVE-2024-26809", "CVE-2024-26810", "CVE-2024-26812", "CVE-2024-26813", "CVE-2024-26814", "CVE-2024-26815", "CVE-2024-26816", "CVE-2024-26859", "CVE-2024-26860", "CVE-2024-26861", "CVE-2024-26862", "CVE-2024-26863", "CVE-2024-26864", "CVE-2024-26865", "CVE-2024-26866", "CVE-2024-26868", "CVE-2024-26869", "CVE-2024-26870", "CVE-2024-26871", "CVE-2024-26872", "CVE-2024-26873", "CVE-2024-26874", "CVE-2024-26875", "CVE-2024-26876", "CVE-2024-26877", "CVE-2024-26878", "CVE-2024-26879", "CVE-2024-26880", "CVE-2024-26881", "CVE-2024-26882", "CVE-2024-26883", "CVE-2024-26884", "CVE-2024-26885", "CVE-2024-26886", "CVE-2024-26887", "CVE-2024-26888", "CVE-2024-26889", "CVE-2024-26890", "CVE-2024-26891", "CVE-2024-26892", "CVE-2024-26893", "CVE-2024-26894", "CVE-2024-26895", "CVE-2024-26896", "CVE-2024-26897", "CVE-2024-26898", "CVE-2024-26899", "CVE-2024-26900", "CVE-2024-26901", "CVE-2024-26927", "CVE-2024-26929", "CVE-2024-26930", "CVE-2024-26931", "CVE-2024-26932", "CVE-2024-26933", "CVE-2024-26934", "CVE-2024-26935", "CVE-2024-26937", "CVE-2024-26938", "CVE-2024-26939", "CVE-2024-26940", "CVE-2024-26941", "CVE-2024-26942", "CVE-2024-26943", "CVE-2024-26944", "CVE-2024-26945", "CVE-2024-26946", "CVE-2024-26947", "CVE-2024-26948", "CVE-2024-26949", "CVE-2024-26950", "CVE-2024-26951", "CVE-2024-26952", "CVE-2024-26953", "CVE-2024-26954", "CVE-2024-26955", "CVE-2024-26956", "CVE-2024-26957", "CVE-2024-26958", "CVE-2024-26959", "CVE-2024-26960", "CVE-2024-26961", "CVE-2024-26962", "CVE-2024-26963", "CVE-2024-26964", "CVE-2024-26965", "CVE-2024-26966", "CVE-2024-26967", "CVE-2024-26968", "CVE-2024-26969", "CVE-2024-26970", "CVE-2024-26971", "CVE-2024-26972", "CVE-2024-26973", "CVE-2024-26975", "CVE-2024-26976", "CVE-2024-26977", "CVE-2024-26978", "CVE-2024-27026", "CVE-2024-27027", "CVE-2024-27028", "CVE-2024-27029", "CVE-2024-27030", "CVE-2024-27031", "CVE-2024-27032", "CVE-2024-27033", "CVE-2024-27034", "CVE-2024-27035", "CVE-2024-27036", "CVE-2024-27037", "CVE-2024-27038", "CVE-2024-27039", "CVE-2024-27040", "CVE-2024-27041", "CVE-2024-27042", "CVE-2024-27043", "CVE-2024-27044", "CVE-2024-27045", "CVE-2024-27046", "CVE-2024-27047", "CVE-2024-27048", "CVE-2024-27049", "CVE-2024-27050", "CVE-2024-27051", "CVE-2024-27052", "CVE-2024-27053", "CVE-2024-27054", "CVE-2024-27058", "CVE-2024-27063", "CVE-2024-27064", "CVE-2024-27065", "CVE-2024-27066", "CVE-2024-27067", "CVE-2024-27068", "CVE-2024-27069", "CVE-2024-27070", "CVE-2024-27071", "CVE-2024-27072", "CVE-2024-27073", "CVE-2024-27074", "CVE-2024-27075", "CVE-2024-27076", "CVE-2024-27077", "CVE-2024-27078", "CVE-2024-27079", "CVE-2024-27080", "CVE-2024-27388", "CVE-2024-27389", "CVE-2024-27390", "CVE-2024-27391", "CVE-2024-27392", "CVE-2024-27432", "CVE-2024-27433", "CVE-2024-27434", "CVE-2024-27435", "CVE-2024-27436", "CVE-2024-27437", "CVE-2024-35787", "CVE-2024-35789", "CVE-2024-35793", "CVE-2024-35794", "CVE-2024-35795", "CVE-2024-35796", "CVE-2024-35797", "CVE-2024-35798", "CVE-2024-35799", "CVE-2024-35800", "CVE-2024-35801", "CVE-2024-35803", "CVE-2024-35805", "CVE-2024-35806", "CVE-2024-35807", "CVE-2024-35808", "CVE-2024-35809", "CVE-2024-35810", "CVE-2024-35811", "CVE-2024-35813", "CVE-2024-35814", "CVE-2024-35817", "CVE-2024-35819", "CVE-2024-35821", "CVE-2024-35822", "CVE-2024-35826", "CVE-2024-35827", "CVE-2024-35828", "CVE-2024-35829", "CVE-2024-35830", "CVE-2024-35831", "CVE-2024-35843", "CVE-2024-35844", "CVE-2024-35845", "CVE-2024-35874");
  script_tag(name:"creation_date", value:"2024-07-08 07:51:46 +0000 (Mon, 08 Jul 2024)");
  script_version("2024-07-09T05:05:54+0000");
  script_tag(name:"last_modification", value:"2024-07-09 05:05:54 +0000 (Tue, 09 Jul 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-23 19:14:05 +0000 (Thu, 23 May 2024)");

  script_name("Ubuntu: Security Advisory (USN-6878-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6878-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6878-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oracle' package(s) announced via the USN-6878-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ziming Zhang discovered that the DRM driver for VMware Virtual GPU did not
properly handle certain error conditions, leading to a NULL pointer
dereference. A local attacker could possibly trigger this vulnerability to
cause a denial of service. (CVE-2022-38096)

Zheng Wang discovered that the Broadcom FullMAC WLAN driver in the Linux
kernel contained a race condition during device removal, leading to a use-
after-free vulnerability. A physically proximate attacker could possibly
use this to cause a denial of service (system crash). (CVE-2023-47233)

It was discovered that the ATA over Ethernet (AoE) driver in the Linux
kernel contained a race condition, leading to a use-after-free
vulnerability. An attacker could use this to cause a denial of service or
possibly execute arbitrary code. (CVE-2023-6270)

It was discovered that the Atheros 802.11ac wireless driver did not
properly validate certain data structures, leading to a NULL pointer
dereference. An attacker could possibly use this to cause a denial of
service. (CVE-2023-7042)

It was discovered that the Intel Data Streaming and Intel Analytics
Accelerator drivers in the Linux kernel allowed direct access to the
devices for unprivileged users and virtual machines. A local attacker could
use this to cause a denial of service. (CVE-2024-21823)

Gui-Dong Han discovered that the software RAID driver in the Linux kernel
contained a race condition, leading to an integer overflow vulnerability. A
privileged attacker could possibly use this to cause a denial of service
(system crash). (CVE-2024-23307)

Bai Jiaju discovered that the Xceive XC4000 silicon tuner device driver in
the Linux kernel contained a race condition, leading to an integer overflow
vulnerability. An attacker could possibly use this to cause a denial of
service (system crash). (CVE-2024-24861)

Chenyuan Yang discovered that the Unsorted Block Images (UBI) flash device
volume management subsystem did not properly validate logical eraseblock
sizes in certain situations. An attacker could possibly use this to cause a
denial of service (system crash). (CVE-2024-25739)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM32 architecture,
 - PowerPC architecture,
 - x86 architecture,
 - Block layer subsystem,
 - ACPI drivers,
 - Bluetooth drivers,
 - Clock framework and drivers,
 - CPU frequency scaling framework,
 - Cryptographic API,
 - DPLL subsystem,
 - ARM SCMI message protocol,
 - EFI core,
 - GPU drivers,
 - InfiniBand drivers,
 - IOMMU subsystem,
 - LED subsystem,
 - Multiple devices driver,
 - Media drivers,
 - MMC subsystem,
 - Network drivers,
 - NTB driver,
 - NVME drivers,
 - PCI subsystem,
 - Powercap sysfs driver,
 - SCSI drivers,
 - Freescale SoC drivers,
 - SPI subsystem,
 - Media staging drivers,
 - Thermal ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-oracle' package(s) on Ubuntu 24.04.");

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

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1006-oracle", ver:"6.8.0-1006.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1006-oracle-64k", ver:"6.8.0-1006.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"6.8.0-1006.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k", ver:"6.8.0-1006.6", rls:"UBUNTU24.04 LTS"))) {
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
