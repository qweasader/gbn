# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5915.1");
  script_cve_id("CVE-2022-36280", "CVE-2022-3707", "CVE-2022-41218", "CVE-2022-4379", "CVE-2022-47929", "CVE-2023-0045", "CVE-2023-0179", "CVE-2023-0210", "CVE-2023-0266", "CVE-2023-0461", "CVE-2023-23454", "CVE-2023-23455");
  script_tag(name:"creation_date", value:"2023-03-06 04:11:16 +0000 (Mon, 06 Mar 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-10 04:57:00 +0000 (Fri, 10 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-5915-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5915-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5915-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-6.1' package(s) announced via the USN-5915-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Upper Level Protocol (ULP) subsystem in the
Linux kernel did not properly handle sockets entering the LISTEN state in
certain protocols, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-0461)

Davide Ornaghi discovered that the netfilter subsystem in the Linux kernel
did not properly handle VLAN headers in some situations. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-0179)

Ziming Zhang discovered that the VMware Virtual GPU DRM driver in the Linux
kernel contained an out-of-bounds write vulnerability. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2022-36280)

Zheng Wang discovered that the Intel i915 graphics driver in the Linux
kernel did not properly handle certain error conditions, leading to a
double-free. A local attacker could possibly use this to cause a denial of
service (system crash). (CVE-2022-3707)

Hyunwoo Kim discovered that the DVB Core driver in the Linux kernel did not
properly perform reference counting in some situations, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2022-41218)

It was discovered that the NFSD implementation in the Linux kernel
contained a use-after-free vulnerability. A remote attacker could possibly
use this to cause a denial of service (system crash) or execute arbitrary
code. (CVE-2022-4379)

It was discovered that the network queuing discipline implementation in the
Linux kernel contained a null pointer dereference in some situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2022-47929)

Jose Oliveira and Rodrigo Branco discovered that the prctl syscall
implementation in the Linux kernel did not properly protect against
indirect branch prediction attacks in some situations. A local attacker
could possibly use this to expose sensitive information. (CVE-2023-0045)

It was discovered that the KSMBD implementation in the Linux kernel did not
properly validate buffer lengths, leading to a heap-based buffer overflow.
A remote attacker could possibly use this to cause a denial of service
(system crash). (CVE-2023-0210)

It was discovered that a use-after-free vulnerability existed in the
Advanced Linux Sound Architecture (ALSA) subsystem. A local attacker could
use this to cause a denial of service (system crash). (CVE-2023-0266)

Kyle Zeng discovered that the class-based queuing discipline implementation
in the Linux kernel contained a type confusion vulnerability in some
situations. An attacker could use this to cause a denial of service (system
crash). (CVE-2023-23454)

Kyle Zeng discovered that the ATM VC queuing discipline ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-oem-6.1' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-1007-oem", ver:"6.1.0-1007.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04c", ver:"6.1.0.1007.7", rls:"UBUNTU22.04 LTS"))) {
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
