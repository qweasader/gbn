# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6704.3");
  script_cve_id("CVE-2023-23000", "CVE-2023-32247", "CVE-2024-1085", "CVE-2024-1086", "CVE-2024-24855");
  script_tag(name:"creation_date", value:"2024-03-26 14:08:48 +0000 (Tue, 26 Mar 2024)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-05 20:41:24 +0000 (Mon, 05 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-6704-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6704-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6704-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oracle, linux-oracle-5.15' package(s) announced via the USN-6704-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the NVIDIA Tegra XUSB pad controller driver in the
Linux kernel did not properly handle return values in certain error
conditions. A local attacker could use this to cause a denial of service
(system crash). (CVE-2023-23000)

Quentin Minster discovered that the KSMBD implementation in the Linux
kernel did not properly handle session setup requests. A remote attacker
could possibly use this to cause a denial of service (memory exhaustion).
(CVE-2023-32247)

Lonial Con discovered that the netfilter subsystem in the Linux kernel did
not properly handle element deactivation in certain cases, leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2024-1085)

Notselwyn discovered that the netfilter subsystem in the Linux kernel did
not properly handle verdict parameters in certain cases, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2024-1086)

It was discovered that a race condition existed in the SCSI Emulex
LightPulse Fibre Channel driver in the Linux kernel when unregistering FCF
and re-scanning an HBA FCF table, leading to a null pointer dereference
vulnerability. A local attacker could use this to cause a denial of service
(system crash). (CVE-2024-24855)");

  script_tag(name:"affected", value:"'linux-oracle, linux-oracle-5.15' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1054-oracle", ver:"5.15.0-1054.60~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.15.0.1054.60~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1054-oracle", ver:"5.15.0-1054.60", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-lts-22.04", ver:"5.15.0.1054.50", rls:"UBUNTU22.04 LTS"))) {
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
