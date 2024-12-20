# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841836");
  script_cve_id("CVE-2014-0055", "CVE-2014-0077", "CVE-2014-0101", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2309", "CVE-2014-2523", "CVE-2014-2672", "CVE-2014-2678", "CVE-2014-2706", "CVE-2014-2851", "CVE-2014-3122");
  script_tag(name:"creation_date", value:"2014-06-02 10:14:18 +0000 (Mon, 02 Jun 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2224-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2224-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2224-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-raring' package(s) announced via the USN-2224-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matthew Daley reported an information leak in the floppy disk driver of the
Linux kernel. An unprivileged local user could exploit this flaw to obtain
potentially sensitive information from kernel memory. (CVE-2014-1738)

Matthew Daley reported a flaw in the handling of ioctl commands by the
floppy disk driver in the Linux kernel. An unprivileged local user could
exploit this flaw to gain administrative privileges if the floppy disk
module is loaded. (CVE-2014-1737)

A flaw was discovered in the vhost-net subsystem of the Linux kernel. Guest
OS users could exploit this flaw to cause a denial of service (host OS
crash). (CVE-2014-0055)

A flaw was discovered in the handling of network packets when mergeable
buffers are disabled for virtual machines in the Linux kernel. Guest OS
users may exploit this flaw to cause a denial of service (host OS crash) or
possibly gain privilege on the host OS. (CVE-2014-0077)

A flaw was discovered in the Linux kernel's handling of the SCTP handshake.
A remote attacker could exploit this flaw to cause a denial of service
(system crash). (CVE-2014-0101)

A flaw was discovered in the handling of routing information in Linux
kernel's IPv6 stack. A remote attacker could exploit this flaw to cause a
denial of service (memory consumption) via a flood of ICMPv6 router
advertisement packets. (CVE-2014-2309)

An error was discovered in the Linux kernel's DCCP protocol support. A
remote attacked could exploit this flaw to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2014-2523)

Max Sydorenko discovered a race condition in the Atheros 9k wireless driver
in the Linux kernel. This race could be exploited by remote attackers to
cause a denial of service (system crash). (CVE-2014-2672)

An error was discovered in the Reliable Datagram Sockets (RDS) protocol
stack in the Linux kernel. A local user could exploit this flaw to cause a
denial of service (system crash) or possibly have unspecified other impact.
(CVE-2014-2678)

Yaara Rozenblum discovered a race condition in the Linux kernel's Generic
IEEE 802.11 Networking Stack (mac80211). Remote attackers could exploit
this flaw to cause a denial of service (system crash). (CVE-2014-2706)

A flaw was discovered in the Linux kernel's ping sockets. An unprivileged
local user could exploit this flaw to cause a denial of service (system
crash) or possibly gain privileges via a crafted application.
(CVE-2014-2851)

Sasha Levin reported a bug in the Linux kernel's virtual memory management
subsystem. An unprivileged local user could exploit this flaw to cause a
denial of service (system crash). (CVE-2014-3122)");

  script_tag(name:"affected", value:"'linux-lts-raring' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.8.0-41-generic", ver:"3.8.0-41.60~precise1", rls:"UBUNTU12.04 LTS"))) {
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
