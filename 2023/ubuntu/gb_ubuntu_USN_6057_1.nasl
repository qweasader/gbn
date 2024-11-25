# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6057.1");
  script_cve_id("CVE-2022-4129", "CVE-2022-47929", "CVE-2022-4842", "CVE-2023-0386", "CVE-2023-0394", "CVE-2023-1073", "CVE-2023-1074", "CVE-2023-1281", "CVE-2023-1652", "CVE-2023-26545");
  script_tag(name:"creation_date", value:"2023-05-08 04:09:30 +0000 (Mon, 08 May 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-24 20:39:53 +0000 (Fri, 24 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-6057-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6057-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6057-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-intel-iotg' package(s) announced via the USN-6057-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Traffic-Control Index (TCINDEX) implementation
in the Linux kernel contained a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-1281)

It was discovered that the OverlayFS implementation in the Linux kernel did
not properly handle copy up operation in some conditions. A local attacker
could possibly use this to gain elevated privileges. (CVE-2023-0386)

Haowei Yan discovered that a race condition existed in the Layer 2
Tunneling Protocol (L2TP) implementation in the Linux kernel. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-4129)

It was discovered that the network queuing discipline implementation in the
Linux kernel contained a null pointer dereference in some situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2022-47929)

It was discovered that the NTFS file system implementation in the Linux
kernel contained a null pointer dereference in some situations. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2022-4842)

Kyle Zeng discovered that the IPv6 implementation in the Linux kernel
contained a NULL pointer dereference vulnerability in certain situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2023-0394)

It was discovered that the Human Interface Device (HID) support driver in
the Linux kernel contained a type confusion vulnerability in some
situations. A local attacker could use this to cause a denial of service
(system crash). (CVE-2023-1073)

It was discovered that a memory leak existed in the SCTP protocol
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (memory exhaustion). (CVE-2023-1074)

It was discovered that the NFS implementation in the Linux kernel did not
properly handle pending tasks in some situations. A local attacker could
use this to cause a denial of service (system crash) or expose sensitive
information (kernel memory). (CVE-2023-1652)

Lianhui Tang discovered that the MPLS implementation in the Linux kernel
did not properly handle certain sysctl allocation failure conditions,
leading to a double-free vulnerability. An attacker could use this to cause
a denial of service or possibly execute arbitrary code. (CVE-2023-26545)");

  script_tag(name:"affected", value:"'linux-intel-iotg' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1028-intel-iotg", ver:"5.15.0-1028.33", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1028.27", rls:"UBUNTU22.04 LTS"))) {
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
