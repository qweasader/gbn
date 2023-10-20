# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5929.1");
  script_cve_id("CVE-2022-3169", "CVE-2022-3344", "CVE-2022-3435", "CVE-2022-3521", "CVE-2022-3545", "CVE-2022-4139", "CVE-2022-4379", "CVE-2022-45869", "CVE-2022-47518", "CVE-2022-47519", "CVE-2022-47520", "CVE-2022-47521", "CVE-2023-0179", "CVE-2023-0461", "CVE-2023-26605");
  script_tag(name:"creation_date", value:"2023-03-07 14:00:00 +0000 (Tue, 07 Mar 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-04 04:09:00 +0000 (Sat, 04 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-5929-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.10");

  script_xref(name:"Advisory-ID", value:"USN-5929-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5929-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi' package(s) announced via the USN-5929-1 advisory.");

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

It was discovered that the NVMe driver in the Linux kernel did not properly
handle reset events in some situations. A local attacker could use this to
cause a denial of service (system crash). (CVE-2022-3169)

Maxim Levitsky discovered that the KVM nested virtualization (SVM)
implementation for AMD processors in the Linux kernel did not properly
handle nested shutdown execution. An attacker in a guest vm could use this
to cause a denial of service (host kernel crash) (CVE-2022-3344)

Gwangun Jung discovered a race condition in the IPv4 implementation in the
Linux kernel when deleting multipath routes, resulting in an out-of-bounds
read. An attacker could use this to cause a denial of service (system
crash) or possibly expose sensitive information (kernel memory).
(CVE-2022-3435)

It was discovered that a race condition existed in the Kernel Connection
Multiplexor (KCM) socket implementation in the Linux kernel when releasing
sockets in certain situations. A local attacker could use this to cause a
denial of service (system crash). (CVE-2022-3521)

It was discovered that the Netronome Ethernet driver in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-3545)

It was discovered that the Intel i915 graphics driver in the Linux kernel
did not perform a GPU TLB flush in some situations. A local attacker could
use this to cause a denial of service or possibly execute arbitrary code.
(CVE-2022-4139)

It was discovered that the NFSD implementation in the Linux kernel
contained a use-after-free vulnerability. A remote attacker could possibly
use this to cause a denial of service (system crash) or execute arbitrary
code. (CVE-2022-4379)

It was discovered that a race condition existed in the x86 KVM subsystem
implementation in the Linux kernel when nested virtualization and the TDP
MMU are enabled. An attacker in a guest vm could use this to cause a denial
of service (host OS crash). (CVE-2022-45869)

It was discovered that the Atmel WILC1000 driver in the Linux kernel did
not properly validate the number of channels, leading to an out-of-bounds
write vulnerability. An attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-raspi' package(s) on Ubuntu 22.10.");

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

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1014-raspi", ver:"5.19.0-1014.21", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1014-raspi-nolpae", ver:"5.19.0-1014.21", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.19.0.1014.13", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.19.0.1014.13", rls:"UBUNTU22.10"))) {
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
