# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2013.2023.1");
  script_cve_id("CVE-2013-0343", "CVE-2013-2147", "CVE-2013-2889", "CVE-2013-2893", "CVE-2013-2894", "CVE-2013-2895", "CVE-2013-2897", "CVE-2013-4270", "CVE-2013-4343");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2023-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU13\.04");

  script_xref(name:"Advisory-ID", value:"USN-2023-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2023-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2023-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An information leak was discovered in the handling of ICMPv6 Router
Advertisement (RA) messages in the Linux kernel's IPv6 network stack. A
remote attacker could exploit this flaw to cause a denial of service
(excessive retries and address-generation outage), and consequently obtain
sensitive information. (CVE-2013-0343)

Dan Carpenter discovered an information leak in the HP Smart Array and
Compaq SMART2 disk-array driver in the Linux kernel. A local user could
exploit this flaw to obtain sensitive information from kernel memory.
(CVE-2013-2147)

Kees Cook discovered flaw in the Human Interface Device (HID) subsystem
when CONFIG_HID_ZEROPLUS is enabled. A physically proximate attacker could
leverage this flaw to cause a denial of service via a specially crafted
device. (CVE-2013-2889)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when any of CONFIG_LOGITECH_FF,
CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF are enabled. A physcially
proximate attacker can leverage this flaw to cause a denial of service vias
a specially crafted device. (CVE-2013-2893)

Kees Cook discovered a flaw in the Human Interface Device (HID) subsystem
of the Linux kernel when CONFIG_HID_LENOVO_TPKBD is enabled. A physically
proximate attacker could exploit this flaw to cause a denial of service via
a specially crafted device. (CVE-2013-2894)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when CONFIG_HID_LOGITECH_DJ is enabled. A
physically proximate attacker could cause a denial of service (OOPS) or
obtain sensitive information from kernel memory via a specially crafted
device. (CVE-2013-2895)

Kees Cook discovered yet another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when CONFIG_HID_MULTITOUCH is enabled. A
physically proximate attacker could leverage this flaw to cause a denial of
service (OOPS) via a specially crafted device. (CVE-2013-2897)

Miroslav Vadkerti discovered a flaw in how the permissions for network
sysctls are handled in the Linux kernel. An unprivileged local user could
exploit this flaw to have privileged access to files in /proc/sys/net/.
(CVE-2013-4270)

Wannes Rombouts reported a vulnerability in the networking tuntap interface
of the Linux kernel. A local user with the CAP_NET_ADMIN capability could
leverage this flaw to gain full admin privileges. (CVE-2013-4343)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.8.0-33-generic", ver:"3.8.0-33.48", rls:"UBUNTU13.04"))) {
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
