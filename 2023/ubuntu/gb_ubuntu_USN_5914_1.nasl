# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5914.1");
  script_cve_id("CVE-2022-3567", "CVE-2022-42896", "CVE-2022-4379", "CVE-2022-43945", "CVE-2022-45934", "CVE-2022-47520", "CVE-2023-0045", "CVE-2023-0461", "CVE-2023-0469");
  script_tag(name:"creation_date", value:"2023-03-06 04:11:16 +0000 (Mon, 06 Mar 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 01:27:00 +0000 (Mon, 28 Nov 2022)");

  script_name("Ubuntu: Security Advisory (USN-5914-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5914-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5914-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-6.0' package(s) announced via the USN-5914-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Upper Level Protocol (ULP) subsystem in the
Linux kernel did not properly handle sockets entering the LISTEN state in
certain protocols, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-0461)

It was discovered that the NFSD implementation in the Linux kernel did not
properly handle some RPC messages, leading to a buffer overflow. A remote
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2022-43945)

Tamas Koczka discovered that the Bluetooth L2CAP handshake implementation
in the Linux kernel contained multiple use-after-free vulnerabilities. A
physically proximate attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-42896)

It was discovered that the IPv6 implementation in the Linux kernel
contained a data race condition. An attacker could possibly use this to
cause undesired behaviors. (CVE-2022-3567)

It was discovered that the NFSD implementation in the Linux kernel
contained a use-after-free vulnerability. A remote attacker could possibly
use this to cause a denial of service (system crash) or execute arbitrary
code. (CVE-2022-4379)

It was discovered that an integer overflow vulnerability existed in the
Bluetooth subsystem in the Linux kernel. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2022-45934)

It was discovered that the Atmel WILC1000 driver in the Linux kernel did
not properly validate offsets, leading to an out-of-bounds read
vulnerability. An attacker could use this to cause a denial of service
(system crash). (CVE-2022-47520)

Jose Oliveira and Rodrigo Branco discovered that the prctl syscall
implementation in the Linux kernel did not properly protect against
indirect branch prediction attacks in some situations. A local attacker
could possibly use this to expose sensitive information. (CVE-2023-0045)

It was discovered that the io_uring subsystem in the Linux kernel contained
a use-after-free vulnerability. A local attacker could possibly use this to
cause a denial of service (system crash) or execute arbitrary code.
(CVE-2023-0469)");

  script_tag(name:"affected", value:"'linux-oem-6.0' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.0.0-1012-oem", ver:"6.0.0-1012.12", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04b", ver:"6.0.0.1012.12", rls:"UBUNTU22.04 LTS"))) {
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
