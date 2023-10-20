# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6093.1");
  script_cve_id("CVE-2022-3108", "CVE-2022-3903", "CVE-2022-4129", "CVE-2023-0458", "CVE-2023-1073", "CVE-2023-1074", "CVE-2023-1281", "CVE-2023-1829", "CVE-2023-26545");
  script_tag(name:"creation_date", value:"2023-05-22 15:03:11 +0000 (Mon, 22 May 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-19 19:16:00 +0000 (Wed, 19 Apr 2023)");

  script_name("Ubuntu: Security Advisory (USN-6093-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6093-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6093-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-bluefield' package(s) announced via the USN-6093-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Traffic-Control Index (TCINDEX) implementation
in the Linux kernel did not properly perform filter deactivation in some
situations. A local attacker could possibly use this to gain elevated
privileges. Please note that with the fix for this CVE, kernel support for
the TCINDEX classifier has been removed. (CVE-2023-1829)

It was discovered that the Traffic-Control Index (TCINDEX) implementation
in the Linux kernel contained a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-1281)

Jiasheng Jiang discovered that the HSA Linux kernel driver for AMD Radeon
GPU devices did not properly validate memory allocation in certain
situations, leading to a null pointer dereference vulnerability. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2022-3108)

It was discovered that the infrared transceiver USB driver did not properly
handle USB control messages. A local attacker with physical access could
plug in a specially crafted USB device to cause a denial of service (memory
exhaustion). (CVE-2022-3903)

Haowei Yan discovered that a race condition existed in the Layer 2
Tunneling Protocol (L2TP) implementation in the Linux kernel. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-4129)

Jordy Zomer and Alexandra Sandulescu discovered that syscalls invoking the
do_prlimit() function in the Linux kernel did not properly handle
speculative execution barriers. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2023-0458)

It was discovered that the Human Interface Device (HID) support driver in
the Linux kernel contained a type confusion vulnerability in some
situations. A local attacker could use this to cause a denial of service
(system crash). (CVE-2023-1073)

It was discovered that a memory leak existed in the SCTP protocol
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (memory exhaustion). (CVE-2023-1074)

Lianhui Tang discovered that the MPLS implementation in the Linux kernel
did not properly handle certain sysctl allocation failure conditions,
leading to a double-free vulnerability. An attacker could use this to cause
a denial of service or possibly execute arbitrary code. (CVE-2023-26545)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1062-bluefield", ver:"5.4.0-1062.68", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-bluefield", ver:"5.4.0.1062.57", rls:"UBUNTU20.04 LTS"))) {
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
