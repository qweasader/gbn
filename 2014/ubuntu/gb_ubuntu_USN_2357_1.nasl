# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.841978");
  script_cve_id("CVE-2014-3601", "CVE-2014-5471", "CVE-2014-5472");
  script_tag(name:"creation_date", value:"2014-09-24 04:03:14 +0000 (Wed, 24 Sep 2014)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2357-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2357-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2357-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-2357-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jack Morgenstein reported a flaw in the page handling of the KVM (Kernel
Virtual Machine) subsystem in the Linux kernel. A guest OS user could
exploit this flaw to cause a denial of service (host OS memory corruption)
or possibly have other unspecified impact on the host OS. (CVE-2014-3601)

Chris Evans reported an flaw in the Linux kernel's handling of iso9660
(compact disk filesystem) images. An attacker who can mount a custom
iso9660 image either via a CD/DVD drive or a loopback mount could cause a
denial of service (system crash or reboot). (CVE-2014-5471)

Chris Evans reported an flaw in the Linux kernel's handling of iso9660
(compact disk filesystem) images. An attacker who can mount a custom
iso9660 image, with a self-referential CL entry, either via a CD/DVD drive
or a loopback mount could cause a denial of service (unkillable mount
process). (CVE-2014-5472)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-1453-omap4", ver:"3.2.0-1453.73", rls:"UBUNTU12.04 LTS"))) {
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
