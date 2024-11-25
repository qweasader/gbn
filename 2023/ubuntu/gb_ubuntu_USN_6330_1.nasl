# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6330.1");
  script_cve_id("CVE-2022-40982", "CVE-2023-20593", "CVE-2023-21400", "CVE-2023-3609", "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-3777", "CVE-2023-3995", "CVE-2023-4004", "CVE-2023-4015");
  script_tag(name:"creation_date", value:"2023-09-01 04:08:43 +0000 (Fri, 01 Sep 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-11 17:59:05 +0000 (Mon, 11 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6330-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6330-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6330-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp-5.15' package(s) announced via the USN-6330-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel Moghimi discovered that some Intel(R) Processors did not properly
clear microarchitectural state after speculative execution of various
instructions. A local unprivileged user could use this to obtain to
sensitive information. (CVE-2022-40982)

Tavis Ormandy discovered that some AMD processors did not properly handle
speculative execution of certain vector register instructions. A local
attacker could use this to expose sensitive information. (CVE-2023-20593)

Ye Zhang and Nicolas Wu discovered that the io_uring subsystem in the Linux
kernel did not properly handle locking for rings with IOPOLL, leading to a
double-free vulnerability. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2023-21400)

It was discovered that the universal 32bit network packet classifier
implementation in the Linux kernel did not properly perform reference
counting in some situations, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-3609)

It was discovered that the netfilter subsystem in the Linux kernel did not
properly handle certain error conditions, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-3610)

It was discovered that the Quick Fair Queueing network scheduler
implementation in the Linux kernel contained an out-of-bounds write
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-3611)

It was discovered that the network packet classifier with
netfilter/firewall marks implementation in the Linux kernel did not
properly handle reference counting, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-3776)

Kevin Rich discovered that the netfilter subsystem in the Linux kernel did
not properly handle table rules flush in certain circumstances. A local
attacker could possibly use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2023-3777)

Kevin Rich discovered that the netfilter subsystem in the Linux kernel did
not properly handle rule additions to bound chains in certain
circumstances. A local attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2023-3995)

It was discovered that the netfilter subsystem in the Linux kernel did not
properly handle PIPAPO element removal, leading to a use-after-free
vulnerability. A local attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2023-4004)

Kevin Rich discovered that the netfilter subsystem in the Linux ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-gcp-5.15' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1040-gcp", ver:"5.15.0-1040.48~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.15.0.1040.48~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
