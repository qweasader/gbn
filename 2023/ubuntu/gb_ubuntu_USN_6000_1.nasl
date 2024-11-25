# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6000.1");
  script_cve_id("CVE-2022-3169", "CVE-2022-3424", "CVE-2022-3435", "CVE-2022-3521", "CVE-2022-3545", "CVE-2022-3623", "CVE-2022-36280", "CVE-2022-41218", "CVE-2022-4139", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-47520", "CVE-2022-47929", "CVE-2023-0045", "CVE-2023-0266", "CVE-2023-0394", "CVE-2023-0461", "CVE-2023-1382", "CVE-2023-20938", "CVE-2023-23454", "CVE-2023-23455", "CVE-2023-26607", "CVE-2023-28328");
  script_tag(name:"creation_date", value:"2023-04-06 04:09:18 +0000 (Thu, 06 Apr 2023)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-06 19:32:27 +0000 (Mon, 06 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-6000-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6000-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6000-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-bluefield' package(s) announced via the USN-6000-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Upper Level Protocol (ULP) subsystem in the
Linux kernel did not properly handle sockets entering the LISTEN state in
certain protocols, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-0461)

It was discovered that the NVMe driver in the Linux kernel did not properly
handle reset events in some situations. A local attacker could use this to
cause a denial of service (system crash). (CVE-2022-3169)

It was discovered that a use-after-free vulnerability existed in the SGI
GRU driver in the Linux kernel. A local attacker could possibly use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-3424)

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

It was discovered that the hugetlb implementation in the Linux kernel
contained a race condition in some situations. A local attacker could use
this to cause a denial of service (system crash) or expose sensitive
information (kernel memory). (CVE-2022-3623)

Ziming Zhang discovered that the VMware Virtual GPU DRM driver in the Linux
kernel contained an out-of-bounds write vulnerability. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2022-36280)

Hyunwoo Kim discovered that the DVB Core driver in the Linux kernel did not
properly perform reference counting in some situations, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2022-41218)

It was discovered that the Intel i915 graphics driver in the Linux kernel
did not perform a GPU TLB flush in some situations. A local attacker could
use this to cause a denial of service or possibly execute arbitrary code.
(CVE-2022-4139)

It was discovered that a race condition existed in the Xen network backend
driver in the Linux kernel when handling dropped packets in certain
circumstances. An attacker could use this to cause a denial of service
(kernel deadlock). (CVE-2022-42328, CVE-2022-42329)

It was discovered ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-bluefield' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1059-bluefield", ver:"5.4.0-1059.65", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-bluefield", ver:"5.4.0.1059.54", rls:"UBUNTU20.04 LTS"))) {
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
