# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841680");
  script_cve_id("CVE-2013-4470", "CVE-2013-4511", "CVE-2013-4513", "CVE-2013-4514", "CVE-2013-4515", "CVE-2013-4516", "CVE-2013-6383", "CVE-2013-6763", "CVE-2013-7027");
  script_tag(name:"creation_date", value:"2014-01-06 10:37:10 +0000 (Mon, 06 Jan 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2073-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU13\.04");

  script_xref(name:"Advisory-ID", value:"USN-2073-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2073-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2073-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hannes Frederic Sowa discovered a flaw in the Linux kernel's UDP
Fragmentation Offload (UFO). An unprivileged local user could exploit this
flaw to cause a denial of service (system crash) or possibly gain
administrative privileges. (CVE-2013-4470)

Multiple integer overflow flaws were discovered in the Alchemy LCD frame-
buffer drivers in the Linux kernel. An unprivileged local user could
exploit this flaw to gain administrative privileges. (CVE-2013-4511)

Nico Golde and Fabian Yamaguchi reported a buffer overflow in the Ozmo
Devices USB over WiFi devices. A local user could exploit this flaw to
cause a denial of service or possibly unspecified impact. (CVE-2013-4513)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
driver for Agere Systems HERMES II Wireless PC Cards. A local user with the
CAP_NET_ADMIN capability could exploit this flaw to cause a denial of
service or possibly gain administrative privileges. (CVE-2013-4514)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
driver for Beceem WIMAX chipset based devices. An unprivileged local user
could exploit this flaw to obtain sensitive information from kernel memory.
(CVE-2013-4515)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
driver for the SystemBase Multi-2/PCI serial card. An unprivileged user
could obtain sensitive information from kernel memory. (CVE-2013-4516)

A flaw was discovered in the Linux kernel's compat ioctls for Adaptec
AACRAID scsi raid devices. An unprivileged local user could send
administrative commands to these devices potentially compromising the data
stored on the device. (CVE-2013-6383)

Nico Golde reported a flaw in the Linux kernel's userspace IO (uio) driver.
A local user could exploit this flaw to cause a denial of service (memory
corruption) or possibly gain privileges. (CVE-2013-6763)

Evan Huus reported a buffer overflow in the Linux kernel's radiotap header
parsing. A remote attacker could cause a denial of service (buffer over-
read) via a specially crafted header. (CVE-2013-7027)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 13.04.");

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

if(release == "UBUNTU13.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.8.0-35-generic", ver:"3.8.0-35.50", rls:"UBUNTU13.04"))) {
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
