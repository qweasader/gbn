# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841906");
  script_cve_id("CVE-2014-1739", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3940", "CVE-2014-4611", "CVE-2014-4943", "CVE-2014-7284");
  script_tag(name:"creation_date", value:"2014-07-21 12:48:55 +0000 (Mon, 21 Jul 2014)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2288-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2288-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2288-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-2288-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sasha Levin reported a flaw in the Linux kernel's point-to-point protocol
(PPP) when used with the Layer Two Tunneling Protocol (L2TP). A local user
could exploit this flaw to gain administrative privileges. (CVE-2014-4943)

Salva Peiro discovered an information leak in the Linux kernel's media-
device driver. A local attacker could exploit this flaw to obtain sensitive
information from kernel memory. (CVE-2014-1739)

A bounds check error was discovered in the socket filter subsystem of the
Linux kernel. A local user could exploit this flaw to cause a denial of
service (system crash) via crafted BPF instructions. (CVE-2014-3144)

A remainder calculation error was discovered in the socket filter subsystem
of the Linux kernel. A local user could exploit this flaw to cause a denial
of service (system crash) via crafted BPF instructions. (CVE-2014-3145)

A flaw was discovered in the Linux kernel's handling of hugetlb entries. A
local user could exploit this flaw to cause a denial service (memory
corruption or system crash). (CVE-2014-3940)

Don Bailey and Ludvig Strigeus discovered an integer overflow in the Linux
kernel's implementation of the LZ4 decompression algorithm, when used by
code not complying with API limitations. An attacker could exploit this
flaw to cause a denial of service (memory corruption) or possibly other
unspecified impact. (CVE-2014-4611)

Tuomas Rasanen reported the Linux kernel on certain Intel processors does
not properly initialize random seeds for network operations, causing TCP
sequence numbers, TCP and UDP port numbers and IP ID values to be
predictable. A remote attacker could exploit this flaw to spoof or disrupt
IP communication. (CVE-2014-7284)");

  script_tag(name:"affected", value:"'linux-lts-trusty' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-32-generic", ver:"3.13.0-32.57~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-32-generic-lpae", ver:"3.13.0-32.57~precise1", rls:"UBUNTU12.04 LTS"))) {
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
