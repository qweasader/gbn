# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.842741");
  script_cve_id("CVE-2013-4312", "CVE-2015-1805", "CVE-2015-7515", "CVE-2015-7566", "CVE-2015-7833", "CVE-2015-8767", "CVE-2015-8812", "CVE-2016-0723", "CVE-2016-0774", "CVE-2016-0821", "CVE-2016-2069", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549", "CVE-2016-2782", "CVE-2016-2847");
  script_tag(name:"creation_date", value:"2016-05-10 03:21:24 +0000 (Tue, 10 May 2016)");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 16:13:00 +0000 (Thu, 19 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-2967-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2967-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2967-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2967-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Linux kernel did not properly enforce rlimits
for file descriptors sent over UNIX domain sockets. A local attacker could
use this to cause a denial of service. (CVE-2013-4312)

Ralf Spenneberg discovered that the Aiptek Tablet USB device driver in the
Linux kernel did not properly validate the endpoints reported by the
device. An attacker with physical access could cause a denial of service
(system crash). (CVE-2015-7515)

Ralf Spenneberg discovered that the USB driver for Clie devices in the
Linux kernel did not properly validate the endpoints reported by the
device. An attacker with physical access could cause a denial of service
(system crash). (CVE-2015-7566)

Ralf Spenneberg discovered that the usbvision driver in the Linux kernel
did not properly validate the interfaces and endpoints reported by the
device. An attacker with physical access could cause a denial of service
(system crash). (CVE-2015-7833)

It was discovered that a race condition existed when handling heartbeat-
timeout events in the SCTP implementation of the Linux kernel. A remote
attacker could use this to cause a denial of service. (CVE-2015-8767)

Venkatesh Pottem discovered a use-after-free vulnerability in the Linux
kernel's CXGB3 driver. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2015-8812)

It was discovered that a race condition existed in the ioctl handler for
the TTY driver in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or expose sensitive information.
(CVE-2016-0723)

It was discovered that the Linux kernel did not keep accurate track of pipe
buffer details when error conditions occurred, due to an incomplete fix for
CVE-2015-1805. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code with administrative
privileges. (CVE-2016-0774)

Zach Riggle discovered that the Linux kernel's list poison feature did not
take into account the mmap_min_addr value. A local attacker could use this
to bypass the kernel's poison-pointer protection mechanism while attempting
to exploit an existing kernel vulnerability. (CVE-2016-0821)

Andy Lutomirski discovered a race condition in the Linux kernel's
translation lookaside buffer (TLB) handling of flush events. A local
attacker could use this to cause a denial of service or possibly leak
sensitive information. (CVE-2016-2069)

Dmitry Vyukov discovered that the Advanced Linux Sound Architecture (ALSA)
framework did not verify that a FIFO was attached to a client before
attempting to clear it. A local attacker could use this to cause a denial
of service (system crash). (CVE-2016-2543)

Dmitry Vyukov discovered that a race condition existed in the Advanced
Linux Sound Architecture (ALSA) framework between timer setup and closing
of the client, resulting in a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-102-generic-pae", ver:"3.2.0-102.142", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-102-generic", ver:"3.2.0-102.142", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-102-highbank", ver:"3.2.0-102.142", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-102-omap", ver:"3.2.0-102.142", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-102-powerpc-smp", ver:"3.2.0-102.142", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-102-powerpc64-smp", ver:"3.2.0-102.142", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-102-virtual", ver:"3.2.0-102.142", rls:"UBUNTU12.04 LTS"))) {
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
