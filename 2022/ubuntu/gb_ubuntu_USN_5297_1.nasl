# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845251");
  script_cve_id("CVE-2021-39685", "CVE-2021-4083", "CVE-2021-4155", "CVE-2021-4202", "CVE-2021-43975", "CVE-2022-0330", "CVE-2022-22942");
  script_tag(name:"creation_date", value:"2022-02-23 02:01:13 +0000 (Wed, 23 Feb 2022)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 14:23:00 +0000 (Thu, 07 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5297-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5297-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5297-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gke, linux-gke-5.4' package(s) announced via the USN-5297-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Szymon Heidrich discovered that the USB Gadget subsystem in the Linux
kernel did not properly restrict the size of control requests for certain
gadget types, leading to possible out of bounds reads or writes. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-39685)

Jann Horn discovered a race condition in the Unix domain socket
implementation in the Linux kernel that could result in a read-after-free.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2021-4083)

Kirill Tkhai discovered that the XFS file system implementation in the
Linux kernel did not calculate size correctly when pre-allocating space in
some situations. A local attacker could use this to expose sensitive
information. (CVE-2021-4155)

Lin Ma discovered that the NFC Controller Interface (NCI) implementation in
the Linux kernel contained a race condition, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2021-4202)

Brendan Dolan-Gavitt discovered that the aQuantia AQtion Ethernet device
driver in the Linux kernel did not properly validate meta-data coming from
the device. A local attacker who can control an emulated device can use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2021-43975)

Sushma Venkatesh Reddy discovered that the Intel i915 graphics driver in
the Linux kernel did not perform a GPU TLB flush in some situations. A
local attacker could use this to cause a denial of service or possibly
execute arbitrary code. (CVE-2022-0330)

It was discovered that the VMware Virtual GPU driver in the Linux kernel
did not properly handle certain failure conditions, leading to a stale
entry in the file descriptor table. A local attacker could use this to
expose sensitive information or possibly gain administrative privileges.
(CVE-2022-22942)");

  script_tag(name:"affected", value:"'linux-gke, linux-gke-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1063-gke", ver:"5.4.0-1063.66~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.4", ver:"5.4.0.1063.66~18.04.27", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1063-gke", ver:"5.4.0-1063.66", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.4.0.1063.73", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.4", ver:"5.4.0.1063.73", rls:"UBUNTU20.04 LTS"))) {
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
