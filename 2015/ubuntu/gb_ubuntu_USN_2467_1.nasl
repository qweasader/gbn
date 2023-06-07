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
  script_oid("1.3.6.1.4.1.25623.1.0.842044");
  script_cve_id("CVE-2014-7841", "CVE-2014-7842", "CVE-2014-7843", "CVE-2014-8884");
  script_tag(name:"creation_date", value:"2015-01-23 11:58:01 +0000 (Fri, 23 Jan 2015)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:C");

  script_name("Ubuntu: Security Advisory (USN-2467-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2467-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2467-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-utopic' package(s) announced via the USN-2467-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A null pointer dereference flaw was discovered in the Linux kernel's
SCTP implementation when ASCONF is used. A remote attacker could exploit
this flaw to cause a denial of service (system crash) via a malformed INIT
chunk. (CVE-2014-7841)

A race condition with MMIO and PIO transactions in the KVM (Kernel Virtual
Machine) subsystem of the Linux kernel was discovered. A guest OS user
could exploit this flaw to cause a denial of service (guest OS crash) via a
specially crafted application. (CVE-2014-7842)

Milos Prchlik reported a flaw in how the ARM64 platform handles a single
byte overflow in __clear_user. A local user could exploit this flaw to
cause a denial of service (system crash) by reading one byte beyond a
/dev/zero page boundary. (CVE-2014-7843)

A stack buffer overflow was discovered in the ioctl command handling for
the Technotrend/Hauppauge USB DEC devices driver. A local user could
exploit this flaw to cause a denial of service (system crash) or possibly
gain privileges. (CVE-2014-8884)");

  script_tag(name:"affected", value:"'linux-lts-utopic' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-29-generic-lpae", ver:"3.16.0-29.39~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-29-generic", ver:"3.16.0-29.39~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-29-lowlatency", ver:"3.16.0-29.39~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-29-powerpc-e500mc", ver:"3.16.0-29.39~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-29-powerpc-smp", ver:"3.16.0-29.39~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-29-powerpc64-emb", ver:"3.16.0-29.39~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-29-powerpc64-smp", ver:"3.16.0-29.39~14.04.1", rls:"UBUNTU14.04 LTS"))) {
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
