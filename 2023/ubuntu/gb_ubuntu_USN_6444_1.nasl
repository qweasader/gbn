# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6444.1");
  script_cve_id("CVE-2023-34319", "CVE-2023-4244", "CVE-2023-42752", "CVE-2023-42753", "CVE-2023-42755", "CVE-2023-42756", "CVE-2023-4622", "CVE-2023-4623", "CVE-2023-4881", "CVE-2023-4921", "CVE-2023-5197");
  script_tag(name:"creation_date", value:"2023-10-20 04:08:37 +0000 (Fri, 20 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 19:38:11 +0000 (Thu, 14 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6444-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6444-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6444-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-6.2, linux-azure, linux-azure-6.2, linux-azure-fde-6.2, linux-gcp, linux-gcp-6.2, linux-hwe-6.2, linux-kvm, linux-lowlatency, linux-lowlatency-hwe-6.2, linux-oracle, linux-raspi, linux-starfive' package(s) announced via the USN-6444-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ross Lagerwall discovered that the Xen netback backend driver in the Linux
kernel did not properly handle certain unusual packets from a
paravirtualized network frontend, leading to a buffer overflow. An attacker
in a guest VM could use this to cause a denial of service (host system
crash) or possibly execute arbitrary code. (CVE-2023-34319)

Bien Pham discovered that the netfiler subsystem in the Linux kernel
contained a race condition, leading to a use-after-free vulnerability. A
local user could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-4244)

Kyle Zeng discovered that the networking stack implementation in the Linux
kernel did not properly validate skb object size in certain conditions. An
attacker could use this cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-42752)

Kyle Zeng discovered that the netfiler subsystem in the Linux kernel did
not properly calculate array offsets, leading to a out-of-bounds write
vulnerability. A local user could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-42753)

Kyle Zeng discovered that the IPv4 Resource Reservation Protocol (RSVP)
classifier implementation in the Linux kernel contained an out-of-bounds
read vulnerability. A local attacker could use this to cause a denial of
service (system crash). Please note that kernel packet classifier support
for RSVP has been removed to resolve this vulnerability. (CVE-2023-42755)

Kyle Zeng discovered that the netfilter subsystem in the Linux kernel
contained a race condition in IP set operations in certain situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2023-42756)

Bing-Jhong Billy Jheng discovered that the Unix domain socket
implementation in the Linux kernel contained a race condition in certain
situations, leading to a use-after-free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-4622)

Budimir Markovic discovered that the qdisc implementation in the Linux
kernel did not properly validate inner classes, leading to a use-after-free
vulnerability. A local user could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-4623)

Alex Birnberg discovered that the netfilter subsystem in the Linux kernel
did not properly validate register length, leading to an out-of- bounds
write vulnerability. A local attacker could possibly use this to cause a
denial of service (system crash). (CVE-2023-4881)

It was discovered that the Quick Fair Queueing scheduler implementation in
the Linux kernel did not properly handle network packets in certain
conditions, leading to a use after free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-6.2, linux-azure, linux-azure-6.2, linux-azure-fde-6.2, linux-gcp, linux-gcp-6.2, linux-hwe-6.2, linux-kvm, linux-lowlatency, linux-lowlatency-hwe-6.2, linux-oracle, linux-raspi, linux-starfive' package(s) on Ubuntu 22.04, Ubuntu 23.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1014-aws", ver:"6.2.0-1014.14~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1015-azure", ver:"6.2.0-1015.15~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1015-azure-fde", ver:"6.2.0-1015.15~22.04.1.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1015-lowlatency", ver:"6.2.0-1015.15~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1015-lowlatency-64k", ver:"6.2.0-1015.15~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1017-gcp", ver:"6.2.0-1017.19~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-35-generic", ver:"6.2.0-35.35~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-35-generic-64k", ver:"6.2.0-35.35~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-35-generic-lpae", ver:"6.2.0-35.35~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.2.0.1014.14~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.2.0.1015.15~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"6.2.0.1015.15~22.04.1.12", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.2.0.1017.19~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-22.04", ver:"6.2.0.35.35~22.04.13", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-22.04", ver:"6.2.0.35.35~22.04.13", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-22.04", ver:"6.2.0.35.35~22.04.13", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-22.04", ver:"6.2.0.1015.15~22.04.12", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-22.04", ver:"6.2.0.1015.15~22.04.12", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-22.04", ver:"6.2.0.35.35~22.04.13", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1007-starfive", ver:"6.2.0-1007.8", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1014-aws", ver:"6.2.0-1014.14", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1014-oracle", ver:"6.2.0-1014.14", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1015-azure", ver:"6.2.0-1015.15", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1015-kvm", ver:"6.2.0-1015.15", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1015-lowlatency", ver:"6.2.0-1015.15", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1015-lowlatency-64k", ver:"6.2.0-1015.15", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1015-raspi", ver:"6.2.0-1015.17", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1017-gcp", ver:"6.2.0-1017.19", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-35-generic", ver:"6.2.0-35.35", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-35-generic-64k", ver:"6.2.0-35.35", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-35-generic-lpae", ver:"6.2.0-35.35", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.2.0.1014.15", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.2.0.1015.15", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.2.0.1017.17", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"6.2.0.35.35", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"6.2.0.35.35", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"6.2.0.35.35", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"6.2.0.1015.15", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"6.2.0.1015.15", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"6.2.0.1015.15", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"6.2.0.1014.14", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"6.2.0.1015.18", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"6.2.0.1015.18", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-starfive", ver:"6.2.0.1007.10", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"6.2.0.35.35", rls:"UBUNTU23.04"))) {
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
