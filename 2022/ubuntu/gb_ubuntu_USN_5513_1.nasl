# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5513.1");
  script_cve_id("CVE-2021-3609", "CVE-2021-3752", "CVE-2021-3760", "CVE-2021-39685", "CVE-2021-39714", "CVE-2021-4197", "CVE-2021-4202", "CVE-2022-0330", "CVE-2022-1353", "CVE-2022-1419", "CVE-2022-1652", "CVE-2022-1679", "CVE-2022-1734", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21166", "CVE-2022-24958", "CVE-2022-28356", "CVE-2022-28388");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-28 19:47:28 +0000 (Mon, 28 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5513-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5513-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5513-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws' package(s) announced via the USN-5513-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Norbert Slusarek discovered a race condition in the CAN BCM networking
protocol of the Linux kernel leading to multiple use-after-free
vulnerabilities. A local attacker could use this issue to execute arbitrary
code. (CVE-2021-3609)

Likang Luo discovered that a race condition existed in the Bluetooth
subsystem of the Linux kernel, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2021-3752)

It was discovered that the NFC subsystem in the Linux kernel contained a
use-after-free vulnerability in its NFC Controller Interface (NCI)
implementation. A local attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2021-3760)

Szymon Heidrich discovered that the USB Gadget subsystem in the Linux
kernel did not properly restrict the size of control requests for certain
gadget types, leading to possible out of bounds reads or writes. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-39685)

It was discovered that the Ion Memory Manager subsystem in the Linux kernel
contained a use-after-free vulnerability. A local attacker could possibly
use this to cause a denial of service (system crash) or execute arbitrary
code. (CVE-2021-39714)

Eric Biederman discovered that the cgroup process migration implementation
in the Linux kernel did not perform permission checks correctly in some
situations. A local attacker could possibly use this to gain administrative
privileges. (CVE-2021-4197)

Lin Ma discovered that the NFC Controller Interface (NCI) implementation in
the Linux kernel contained a race condition, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2021-4202)

Sushma Venkatesh Reddy discovered that the Intel i915 graphics driver in
the Linux kernel did not perform a GPU TLB flush in some situations. A
local attacker could use this to cause a denial of service or possibly
execute arbitrary code. (CVE-2022-0330)

It was discovered that the PF_KEYv2 implementation in the Linux kernel did
not properly initialize kernel memory in some situations. A local attacker
could use this to expose sensitive information (kernel memory).
(CVE-2022-1353)

It was discovered that the virtual graphics memory manager implementation
in the Linux kernel was subject to a race condition, potentially leading to
an information leak. (CVE-2022-1419)

Minh Yuan discovered that the floppy disk driver in the Linux kernel
contained a race condition, leading to a use-after-free vulnerability. A
local attacker could possibly use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2022-1652)

It was discovered that the Atheros ath9k wireless device ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-aws' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1109-aws", ver:"4.4.0-1109.115", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1109.106", rls:"UBUNTU14.04 LTS"))) {
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
