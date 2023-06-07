# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.844992");
  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26139", "CVE-2020-26141", "CVE-2020-26145", "CVE-2020-26147", "CVE-2021-23133", "CVE-2021-23134", "CVE-2021-31829", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-33200", "CVE-2021-3506", "CVE-2021-3609");
  script_tag(name:"creation_date", value:"2021-06-26 03:00:38 +0000 (Sat, 26 Jun 2021)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-06 08:15:00 +0000 (Tue, 06 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-5000-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5000-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5000-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-kvm' package(s) announced via the USN-5000-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5000-1 fixed vulnerabilities in the Linux kernel for Ubuntu
20.04 LTS and the Linux HWE kernel for Ubuntu 18.04 LTS. This update
provides the corresponding updates for the Linux KVM kernel for Ubuntu
20.04 LTS.

Norbert Slusarek discovered a race condition in the CAN BCM networking
protocol of the Linux kernel leading to multiple use-after-free
vulnerabilities. A local attacker could use this issue to execute arbitrary
code. (CVE-2021-3609)

Piotr Krysiuk discovered that the eBPF implementation in the Linux kernel
did not properly enforce limits for pointer operations. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2021-33200)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation did
not properly clear received fragments from memory in some situations. A
physically proximate attacker could possibly use this issue to inject
packets or expose sensitive information. (CVE-2020-24586)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation
incorrectly handled encrypted fragments. A physically proximate attacker
could possibly use this issue to decrypt fragments. (CVE-2020-24587)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation
incorrectly handled certain malformed frames. If a user were tricked into
connecting to a malicious server, a physically proximate attacker could use
this issue to inject packets. (CVE-2020-24588)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation
incorrectly handled EAPOL frames from unauthenticated senders. A physically
proximate attacker could inject malicious packets to cause a denial of
service (system crash). (CVE-2020-26139)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation did
not properly verify certain fragmented frames. A physically proximate
attacker could possibly use this issue to inject or decrypt packets.
(CVE-2020-26141)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation
accepted plaintext fragments in certain situations. A physically proximate
attacker could use this issue to inject packets. (CVE-2020-26145)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation could
reassemble mixed encrypted and plaintext fragments. A physically proximate
attacker could possibly use this issue to inject packets or exfiltrate
selected fragments. (CVE-2020-26147)

Or Cohen discovered that the SCTP implementation in the Linux kernel
contained a race condition in some situations, leading to a use-after-free
condition. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2021-23133)

Or Cohen and Nadav Markus discovered a use-after-free vulnerability in the
nfc implementation in the Linux kernel. A privileged local attacker could
use this issue to cause a denial of service (system crash) or ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-kvm' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1041-kvm", ver:"5.4.0-1041.42", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.4.0.1041.39", rls:"UBUNTU20.04 LTS"))) {
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
