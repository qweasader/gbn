# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6767.2");
  script_cve_id("CVE-2023-52435", "CVE-2023-52486", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52594", "CVE-2023-52595", "CVE-2023-52597", "CVE-2023-52598", "CVE-2023-52599", "CVE-2023-52601", "CVE-2023-52602", "CVE-2023-52604", "CVE-2023-52606", "CVE-2023-52607", "CVE-2023-52615", "CVE-2023-52617", "CVE-2023-52619", "CVE-2023-52622", "CVE-2023-52623", "CVE-2023-52637", "CVE-2024-23849", "CVE-2024-26593", "CVE-2024-26598", "CVE-2024-26600", "CVE-2024-26602", "CVE-2024-26606", "CVE-2024-26615", "CVE-2024-26625", "CVE-2024-26635", "CVE-2024-26636", "CVE-2024-26645", "CVE-2024-26663", "CVE-2024-26664", "CVE-2024-26671", "CVE-2024-26673", "CVE-2024-26675", "CVE-2024-26679", "CVE-2024-26684", "CVE-2024-26685", "CVE-2024-26696", "CVE-2024-26697", "CVE-2024-26702", "CVE-2024-26704", "CVE-2024-26720", "CVE-2024-26722", "CVE-2024-26825", "CVE-2024-26910", "CVE-2024-26920");
  script_tag(name:"creation_date", value:"2024-05-15 04:07:47 +0000 (Wed, 15 May 2024)");
  script_version("2024-05-15T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-05-15 05:05:27 +0000 (Wed, 15 May 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-17 19:40:31 +0000 (Wed, 17 Apr 2024)");

  script_name("Ubuntu: Security Advisory (USN-6767-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6767-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6767-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-bluefield' package(s) announced via the USN-6767-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chenyuan Yang discovered that the RDS Protocol implementation in the Linux
kernel contained an out-of-bounds read vulnerability. An attacker could use
this to possibly cause a denial of service (system crash). (CVE-2024-23849)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - PowerPC architecture,
 - S390 architecture,
 - Block layer subsystem,
 - Android drivers,
 - Hardware random number generator core,
 - GPU drivers,
 - Hardware monitoring drivers,
 - I2C subsystem,
 - IIO Magnetometer sensors drivers,
 - InfiniBand drivers,
 - Network drivers,
 - PCI driver for MicroSemi Switchtec,
 - PHY drivers,
 - Ceph distributed file system,
 - Ext4 file system,
 - JFS file system,
 - NILFS2 file system,
 - Pstore file system,
 - Core kernel,
 - Memory management,
 - CAN network layer,
 - Networking core,
 - IPv4 networking,
 - Logical Link layer,
 - Netfilter,
 - NFC subsystem,
 - SMC sockets,
 - Sun RPC protocol,
 - TIPC protocol,
 - Realtek audio codecs,
(CVE-2024-26696, CVE-2023-52583, CVE-2024-26720, CVE-2023-52615,
CVE-2023-52599, CVE-2023-52587, CVE-2024-26635, CVE-2024-26704,
CVE-2024-26625, CVE-2024-26825, CVE-2023-52622, CVE-2023-52435,
CVE-2023-52617, CVE-2023-52598, CVE-2024-26645, CVE-2023-52619,
CVE-2024-26593, CVE-2024-26685, CVE-2023-52602, CVE-2023-52486,
CVE-2024-26697, CVE-2024-26675, CVE-2024-26600, CVE-2023-52604,
CVE-2024-26664, CVE-2024-26606, CVE-2023-52594, CVE-2024-26671,
CVE-2024-26598, CVE-2024-26673, CVE-2024-26920, CVE-2024-26722,
CVE-2023-52601, CVE-2024-26602, CVE-2023-52637, CVE-2023-52623,
CVE-2024-26702, CVE-2023-52597, CVE-2024-26684, CVE-2023-52606,
CVE-2024-26679, CVE-2024-26663, CVE-2024-26910, CVE-2024-26615,
CVE-2023-52595, CVE-2023-52607, CVE-2024-26636)");

  script_tag(name:"affected", value:"'linux-bluefield' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1084-bluefield", ver:"5.4.0-1084.91", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-bluefield", ver:"5.4.0.1084.80", rls:"UBUNTU20.04 LTS"))) {
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
