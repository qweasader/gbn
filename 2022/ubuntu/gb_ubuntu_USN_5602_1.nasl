# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5602.1");
  script_cve_id("CVE-2021-33061", "CVE-2022-1012", "CVE-2022-1729", "CVE-2022-1852", "CVE-2022-1943", "CVE-2022-1973", "CVE-2022-2503", "CVE-2022-2873", "CVE-2022-2959");
  script_tag(name:"creation_date", value:"2022-09-16 08:45:11 +0000 (Fri, 16 Sep 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 16:34:07 +0000 (Fri, 30 Sep 2022)");

  script_name("Ubuntu: Security Advisory (USN-5602-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5602-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5602-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi' package(s) announced via the USN-5602-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Asaf Modelevsky discovered that the Intel(R) 10GbE PCI Express (ixgbe)
Ethernet driver for the Linux kernel performed insufficient control flow
management. A local attacker could possibly use this to cause a denial of
service. (CVE-2021-33061)

Moshe Kol, Amit Klein and Yossi Gilad discovered that the IP implementation
in the Linux kernel did not provide sufficient randomization when
calculating port offsets. An attacker could possibly use this to expose
sensitive information. (CVE-2022-1012)

Norbert Slusarek discovered that a race condition existed in the perf
subsystem in the Linux kernel, resulting in a use-after-free vulnerability.
A privileged local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-1729)

Qiuhao Li, Gaoning Pan, and Yongkang Jia discovered that the KVM hypervisor
implementation in the Linux kernel did not properly handle an illegal
instruction in a guest, resulting in a null pointer dereference. An
attacker in a guest VM could use this to cause a denial of service (system
crash) in the host OS. (CVE-2022-1852)

It was discovered that the UDF file system implementation in the Linux
kernel contained an out-of-bounds write vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2022-1943)

Gerald Lee discovered that the NTFS file system implementation in the Linux
kernel did not properly handle certain error conditions, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly expose sensitive information.
(CVE-2022-1973)

It was discovered that the device-mapper verity (dm-verity) driver in the
Linux kernel did not properly verify targets being loaded into the device-
mapper table. A privileged attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2022-2503)

Zheyu Ma discovered that the Intel iSMT SMBus host controller driver in the
Linux kernel contained an out-of-bounds write vulnerability. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2022-2873)

Selim Enes Karaduman discovered that a race condition existed in the pipe
buffers implementation of the Linux kernel. A local attacker could use this
to cause a denial of service (system crash) or possibly escalate
privileges. (CVE-2022-2959)");

  script_tag(name:"affected", value:"'linux-raspi' package(s) on Ubuntu 22.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1014-raspi", ver:"5.15.0-1014.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1014-raspi-nolpae", ver:"5.15.0-1014.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.15.0.1014.13", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.15.0.1014.13", rls:"UBUNTU22.04 LTS"))) {
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
