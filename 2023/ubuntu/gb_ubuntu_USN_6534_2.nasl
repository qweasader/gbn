# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6534.2");
  script_cve_id("CVE-2023-37453", "CVE-2023-3773", "CVE-2023-39189", "CVE-2023-39192", "CVE-2023-39193", "CVE-2023-39194", "CVE-2023-39198", "CVE-2023-42754", "CVE-2023-5158", "CVE-2023-5178", "CVE-2023-5717", "CVE-2023-6039");
  script_tag(name:"creation_date", value:"2023-12-13 04:09:07 +0000 (Wed, 13 Dec 2023)");
  script_version("2024-06-19T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-06-19 05:05:42 +0000 (Wed, 19 Jun 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-18 15:10:41 +0000 (Tue, 18 Jun 2024)");

  script_name("Ubuntu: Security Advisory (USN-6534-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU23\.04");

  script_xref(name:"Advisory-ID", value:"USN-6534-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6534-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp, linux-kvm' package(s) announced via the USN-6534-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the USB subsystem in the Linux kernel contained a
race condition while handling device descriptors in certain situations,
leading to a out-of-bounds read vulnerability. A local attacker could
possibly use this to cause a denial of service (system crash).
(CVE-2023-37453)

Lin Ma discovered that the Netlink Transformation (XFRM) subsystem in the
Linux kernel did not properly initialize a policy data structure, leading
to an out-of-bounds vulnerability. A local privileged attacker could use
this to cause a denial of service (system crash) or possibly expose
sensitive information (kernel memory). (CVE-2023-3773)

Lucas Leong discovered that the netfilter subsystem in the Linux kernel did
not properly validate some attributes passed from userspace. A local
attacker could use this to cause a denial of service (system crash) or
possibly expose sensitive information (kernel memory). (CVE-2023-39189)

Sunjoo Park discovered that the netfilter subsystem in the Linux kernel did
not properly validate u32 packets content, leading to an out-of-bounds read
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly expose sensitive information. (CVE-2023-39192)

Lucas Leong discovered that the netfilter subsystem in the Linux kernel did
not properly validate SCTP data, leading to an out-of-bounds read
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly expose sensitive information. (CVE-2023-39193)

Lucas Leong discovered that the Netlink Transformation (XFRM) subsystem in
the Linux kernel did not properly handle state filters, leading to an out-
of-bounds read vulnerability. A privileged local attacker could use this to
cause a denial of service (system crash) or possibly expose sensitive
information. (CVE-2023-39194)

It was discovered that a race condition existed in QXL virtual GPU driver
in the Linux kernel, leading to a use after free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-39198)

Kyle Zeng discovered that the IPv4 implementation in the Linux kernel did
not properly handle socket buffers (skb) when performing IP routing in
certain circumstances, leading to a null pointer dereference vulnerability.
A privileged attacker could use this to cause a denial of service (system
crash). (CVE-2023-42754)

Jason Wang discovered that the virtio ring implementation in the Linux
kernel did not properly handle iov buffers in some situations. A local
attacker in a guest VM could use this to cause a denial of service (host
system crash). (CVE-2023-5158)

Alon Zahavi discovered that the NVMe-oF/TCP subsystem in the Linux kernel
did not properly handle queue initialization failures in certain
situations, leading to a use-after-free vulnerability. A remote attacker
could use this to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-gcp, linux-kvm' package(s) on Ubuntu 23.04.");

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

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1018-kvm", ver:"6.2.0-1018.18", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.2.0-1020-gcp", ver:"6.2.0-1020.22", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.2.0.1020.20", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"6.2.0.1018.18", rls:"UBUNTU23.04"))) {
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
