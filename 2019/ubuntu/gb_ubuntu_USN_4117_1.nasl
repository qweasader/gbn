# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844158");
  script_cve_id("CVE-2019-10126", "CVE-2019-10638", "CVE-2019-12984", "CVE-2019-13233", "CVE-2019-13272", "CVE-2019-14283", "CVE-2019-14284", "CVE-2019-3846", "CVE-2019-3900");
  script_tag(name:"creation_date", value:"2019-09-03 02:01:57 +0000 (Tue, 03 Sep 2019)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-28 12:20:00 +0000 (Thu, 28 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-4117-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU19\.04");

  script_xref(name:"Advisory-ID", value:"USN-4117-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4117-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws' package(s) announced via the USN-4117-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a heap buffer overflow existed in the Marvell
Wireless LAN device driver for the Linux kernel. An attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2019-10126)

Amit Klein and Benny Pinkas discovered that the Linux kernel did not
sufficiently randomize IP ID values generated for connectionless networking
protocols. A remote attacker could use this to track particular Linux
devices. (CVE-2019-10638)

It was discovered that a NULL pointer dereference vulnerability existed in
the Near-field communication (NFC) implementation in the Linux kernel. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2019-12984)

Jann Horn discovered a use-after-free vulnerability in the Linux kernel
when accessing LDT entries in some situations. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2019-13233)

Jann Horn discovered that the ptrace implementation in the Linux kernel did
not properly record credentials in some situations. A local attacker could
use this to cause a denial of service (system crash) or possibly gain
administrative privileges. (CVE-2019-13272)

It was discovered that the floppy driver in the Linux kernel did not
properly validate meta data, leading to a buffer overread. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2019-14283)

It was discovered that the floppy driver in the Linux kernel did not
properly validate ioctl() calls, leading to a division-by-zero. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2019-14284)

It was discovered that the Marvell Wireless LAN device driver in the Linux
kernel did not properly validate the BSS descriptor. A local attacker could
possibly use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2019-3846)

Jason Wang discovered that an infinite loop vulnerability existed in the
virtio net driver in the Linux kernel. A local attacker in a guest VM could
possibly use this to cause a denial of service in the host system.
(CVE-2019-3900)");

  script_tag(name:"affected", value:"'linux-aws' package(s) on Ubuntu 19.04.");

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

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1014-aws", ver:"5.0.0-1014.16", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.0.0.1014.15", rls:"UBUNTU19.04"))) {
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
