# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.842106");
  script_cve_id("CVE-2013-7421", "CVE-2014-7970", "CVE-2014-8160", "CVE-2014-9529", "CVE-2014-9584", "CVE-2014-9585", "CVE-2014-9644", "CVE-2015-0239");
  script_tag(name:"creation_date", value:"2015-02-27 04:42:56 +0000 (Fri, 27 Feb 2015)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 18:14:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-2514-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2514-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2514-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-2514-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in the Kernel Virtual Machine's (KVM) emulation of
the SYSTENTER instruction when the guest OS does not initialize the
SYSENTER MSRs. A guest OS user could exploit this flaw to cause a denial of
service of the guest OS (crash) or potentially gain privileges on the guest
OS. (CVE-2015-0239)

A flaw was discovered in the automatic loading of modules in the crypto
subsystem of the Linux kernel. A local user could exploit this flaw to load
installed kernel modules, increasing the attack surface and potentially
using this to gain administrative privileges. (CVE-2013-7421)

Andy Lutomirski discovered a flaw in how the Linux kernel handles
pivot_root when used with a chroot directory. A local user could exploit
this flaw to cause a denial of service (mount-tree loop). (CVE-2014-7970)

A restriction bypass was discovered in iptables when conntrack rules are
specified and the conntrack protocol handler module is not loaded into the
Linux kernel. This flaw can cause the firewall rules on the system to be
bypassed when conntrack rules are used. (CVE-2014-8160)

A race condition was discovered in the Linux kernel's key ring. A local
user could cause a denial of service (memory corruption or panic) or
possibly have unspecified impact via the keyctl commands. (CVE-2014-9529)

A memory leak was discovered in the ISO 9660 CDROM file system when parsing
rock ridge ER records. A local user could exploit this flaw to obtain
sensitive information from kernel memory via a crafted iso9660 image.
(CVE-2014-9584)

A flaw was discovered in the Address Space Layout Randomization (ASLR) of
the Virtual Dynamically linked Shared Objects (vDSO) location. This flaw
makes it easier for a local user to bypass the ASLR protection mechanism.
(CVE-2014-9585)

A flaw was discovered in the crypto subsystem when screening module names
for automatic module loading if the name contained a valid crypto module
name, eg. vfat(aes). A local user could exploit this flaw to load installed
kernel modules, increasing the attack surface and potentially using this to
gain administrative privileges. (CVE-2014-9644)");

  script_tag(name:"affected", value:"'linux-ti-omap4' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-1460-omap4", ver:"3.2.0-1460.80", rls:"UBUNTU12.04 LTS"))) {
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
