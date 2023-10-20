# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841602");
  script_cve_id("CVE-2013-2237", "CVE-2013-2888", "CVE-2013-2892", "CVE-2013-2896", "CVE-2013-2898", "CVE-2013-2899", "CVE-2013-4300");
  script_tag(name:"creation_date", value:"2013-10-29 11:02:47 +0000 (Tue, 29 Oct 2013)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1995-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1995-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1995-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-raring' package(s) announced via the USN-1995-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An information leak was discovered in the Linux kernel when reading
broadcast messages from the notify_policy interface of the IPSec
key_socket. A local user could exploit this flaw to examine potentially
sensitive information in kernel memory. (CVE-2013-2237)

Kees Cook discovered flaw in the Human Interface Device (HID) subsystem of
the Linux kernel. A physically proximate attacker could exploit this flaw
to execute arbitrary code or cause a denial of service (heap memory
corruption) via a specially crafted device that provides an invalid Report
ID. (CVE-2013-2888)

Kees Cook discovered a flaw in the Human Interface Device (HID) subsystem
of the Linux kernel when CONFIG_HID_PANTHERLORD is enabled. A physically
proximate attacker could cause a denial of service (heap out-of-bounds
write) via a specially crafted device. (CVE-2013-2892)

Kees Cook discovered a vulnerability in the Linux Kernel's Human Interface
Device (HID) subsystem's support for N-Trig touch screens. A physically
proximate attacker could exploit this flaw to cause a denial of service
(OOPS) via a specially crafted device. (CVE-2013-2896)

Kees Cook discovered an information leak in the Linux kernel's Human
Interface Device (HID) subsystem when CONFIG_HID_SENSOR_HUB is enabled. A
physically proximate attacker could obtain potentially sensitive
information from kernel memory via a specially crafted device.
(CVE-2013-2898)

Kees Cook discovered a flaw in the Human Interface Device (HID) subsystem
of the Linux kernel whenCONFIG_HID_PICOLCD is enabled. A physically
proximate attacker could exploit this flaw to cause a denial of service
(OOPS) via a specially crafted device. (CVE-2013-2899)

A flaw was discovered in how the Linux Kernel's networking stack checks scm
credentials when used with namespaces. A local attacker could exploit this
flaw to gain privileges. (CVE-2013-4300)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.8.0-32-generic", ver:"3.8.0-32.47~precise1", rls:"UBUNTU12.04 LTS"))) {
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
