# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.574");
  script_cve_id("CVE-2015-5239", "CVE-2016-2857", "CVE-2016-4020", "CVE-2016-4439", "CVE-2016-5403", "CVE-2016-6351");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:20:44+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:44 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 19:19:00 +0000 (Thu, 15 Oct 2020)");

  script_name("Debian: Security Advisory (DLA-574)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-574");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-574");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu-kvm' package(s) announced via the DLA-574 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in qemu-kvm, a full virtualization solution on x86 hardware. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-5239

Lian Yihan discovered that QEMU incorrectly handled certain payload messages in the VNC display driver. A malicious guest could use this issue to cause the QEMU process to hang, resulting in a denial of service.

CVE-2016-2857

Ling Liu discovered that QEMU incorrectly handled IP checksum routines. An attacker inside the guest could use this issue to cause QEMU to crash, resulting in a denial of service, or possibly leak host memory bytes.

CVE-2016-4020

Donghai Zdh discovered that QEMU incorrectly handled the Task Priority Register(TPR). A privileged attacker inside the guest could use this issue to possibly leak host memory bytes.

CVE-2016-4439 / CVE-2016-6351 Li Qiang disovered that the emulation of the 53C9X Fast SCSI Controller is affected by out of bound access issues.

CVE-2016-5403

Zhenhao Hong discovered that a malicious guest administrator can cause unbounded memory allocation in QEMU (which can cause an Out-of-Memory condition) by submitting virtio requests without bothering to wait for completion.

For Debian 7 Wheezy, these problems have been fixed in version 1.1.2+dfsg-6+deb7u14.

We recommend that you upgrade your qemu-kvm packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"kvm", ver:"1:1.1.2+dfsg-6+deb7u14", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm-dbg", ver:"1.1.2+dfsg-6+deb7u14", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1.1.2+dfsg-6+deb7u14", rls:"DEB7"))) {
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
