# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.841304");
  script_cve_id("CVE-2012-0957", "CVE-2012-4461", "CVE-2012-4508", "CVE-2012-4530", "CVE-2012-4565", "CVE-2012-5517", "CVE-2012-5532");
  script_tag(name:"creation_date", value:"2013-02-04 04:27:45 +0000 (Mon, 04 Feb 2013)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1704-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1704-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1704-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1101666");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-quantal' package(s) announced via the USN-1704-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1704-1 fixed vulnerabilities in the Linux kernel. Due to an unrelated
regression inotify/fanotify stopped working after upgrading. This update
fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Brad Spengler discovered a flaw in the Linux kernel's uname system call. An
 unprivileged user could exploit this flaw to read kernel stack memory.
 (CVE-2012-0957)

 Jon Howell reported a flaw in the Linux kernel's KVM (Kernel-based virtual
 machine) subsystem's handling of the XSAVE feature. On hosts, using qemu
 userspace, without the XSAVE feature an unprivileged local attacker could
 exploit this flaw to crash the system. (CVE-2012-4461)

 Dmitry Monakhov reported a race condition flaw the Linux ext4 filesystem
 that can expose stale data. An unprivileged user could exploit this flaw to
 cause an information leak. (CVE-2012-4508)

 A flaw was discovered in the Linux kernel's handling of script execution
 when module loading is enabled. A local attacker could exploit this flaw to
 cause a leak of kernel stack contents. (CVE-2012-4530)

 Rodrigo Freire discovered a flaw in the Linux kernel's TCP illinois
 congestion control algorithm. A local attacker could use this to cause a
 denial of service. (CVE-2012-4565)

 A flaw was discovered in the Linux kernel's handling of new hot-plugged
 memory. An unprivileged local user could exploit this flaw to cause a
 denial of service by crashing the system. (CVE-2012-5517)

 Florian Weimer discovered that hypervkvpd, which is distributed in the
 Linux kernel, was not correctly validating source addresses of netlink
 packets. An untrusted local user can cause a denial of service by causing
 hypervkvpd to exit. (CVE-2012-5532)");

  script_tag(name:"affected", value:"'linux-lts-quantal' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-23-generic", ver:"3.5.0-23.35~precise1", rls:"UBUNTU12.04 LTS"))) {
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
