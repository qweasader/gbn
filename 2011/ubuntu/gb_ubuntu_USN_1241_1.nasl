# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840790");
  script_cve_id("CVE-2011-1573", "CVE-2011-1576", "CVE-2011-1776", "CVE-2011-2213", "CVE-2011-2494", "CVE-2011-2495", "CVE-2011-2496", "CVE-2011-2497", "CVE-2011-2517", "CVE-2011-2525", "CVE-2011-2695", "CVE-2011-2723", "CVE-2011-2905", "CVE-2011-2909", "CVE-2011-2928", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3363", "CVE-2011-3593");
  script_tag(name:"creation_date", value:"2011-10-31 12:45:00 +0000 (Mon, 31 Oct 2011)");
  script_version("2022-09-16T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:39 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 10:59:00 +0000 (Fri, 31 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-1241-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1241-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1241-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-fsl-imx51' package(s) announced via the USN-1241-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Stream Control Transmission Protocol (SCTP)
implementation incorrectly calculated lengths. If the net.sctp.addip_enable
variable was turned on, a remote attacker could send specially crafted
traffic to crash the system. (CVE-2011-1573)

Ryan Sweat discovered that the kernel incorrectly handled certain VLAN
packets. On some systems, a remote attacker could send specially crafted
traffic to crash the system, leading to a denial of service.
(CVE-2011-1576)

Timo Warns discovered that the EFI GUID partition table was not correctly
parsed. A physically local attacker that could insert mountable devices
could exploit this to crash the system or possibly gain root privileges.
(CVE-2011-1776)

Dan Rosenberg discovered that the IPv4 diagnostic routines did not
correctly validate certain requests. A local attacker could exploit this to
consume CPU resources, leading to a denial of service. (CVE-2011-2213)

Vasiliy Kulikov discovered that taskstats did not enforce access
restrictions. A local attacker could exploit this to read certain
information, leading to a loss of privacy. (CVE-2011-2494)

Vasiliy Kulikov discovered that /proc/PID/io did not enforce access
restrictions. A local attacker could exploit this to read certain
information, leading to a loss of privacy. (CVE-2011-2495)

Robert Swiecki discovered that mapping extensions were incorrectly handled.
A local attacker could exploit this to crash the system, leading to a
denial of service. (CVE-2011-2496)

Dan Rosenberg discovered that the Bluetooth stack incorrectly handled
certain L2CAP requests. If a system was using Bluetooth, a remote attacker
could send specially crafted traffic to crash the system or gain root
privileges. (CVE-2011-2497)

It was discovered that the wireless stack incorrectly verified SSID
lengths. A local attacker could exploit this to cause a denial of service
or gain root privileges. (CVE-2011-2517)

Ben Pfaff discovered that Classless Queuing Disciplines (qdiscs) were being
incorrectly handled. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2011-2525)

It was discovered that the EXT4 filesystem contained multiple off-by-one
flaws. A local attacker could exploit this to crash the system, leading to
a denial of service. (CVE-2011-2695)

Herbert Xu discovered that certain fields were incorrectly handled when
Generic Receive Offload (CVE-2011-2723)

Christian Ohm discovered that the perf command looks for configuration
files in the current directory. If a privileged user were tricked into
running perf in a directory containing a malicious configuration file, an
attacker could run arbitrary commands and possibly gain privileges.
(CVE-2011-2905)

Vasiliy Kulikov discovered that the Comedi driver did not correctly clear
memory. A local attacker could exploit this to read kernel stack memory,
leading to a loss of privacy. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-fsl-imx51' package(s) on Ubuntu 10.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-611-imx51", ver:"2.6.31-611.29", rls:"UBUNTU10.04 LTS"))) {
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
