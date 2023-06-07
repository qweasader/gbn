# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892483");
  script_cve_id("CVE-2019-19039", "CVE-2019-19377", "CVE-2019-19770", "CVE-2019-19816", "CVE-2020-0423", "CVE-2020-14351", "CVE-2020-25656", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-25705", "CVE-2020-27673", "CVE-2020-27675", "CVE-2020-27777", "CVE-2020-28941", "CVE-2020-28974", "CVE-2020-4788", "CVE-2020-8694");
  script_tag(name:"creation_date", value:"2020-12-14 09:20:30 +0000 (Mon, 14 Dec 2020)");
  script_version("2023-03-09T10:20:43+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:43 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-15 22:27:00 +0000 (Mon, 15 Mar 2021)");

  script_name("Debian: Security Advisory (DLA-2483)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2483");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2483");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux-4.19");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-4.19' package(s) announced via the DLA-2483 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to the execution of arbitrary code, privilege escalation, denial of service or information leaks.

CVE-2019-19039

Team bobfuzzer reported a bug in Btrfs that could lead to an assertion failure (WARN). A user permitted to mount and access arbitrary filesystems could use this to cause a denial of service (crash) if the panic_on_warn kernel parameter is set.

CVE-2019-19377

Team bobfuzzer reported a bug in Btrfs that could lead to a use-after-free. A user permitted to mount and access arbitrary filesystems could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2019-19770

The syzbot tool discovered a race condition in the block I/O tracer (blktrace) that could lead to a system crash. Since blktrace can only be controlled by privileged users, the security impact of this is unclear.

CVE-2019-19816

Team bobfuzzer reported a bug in Btrfs that could lead to an out-of-bounds write. A user permitted to mount and access arbitrary filesystems could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2020-0423

A race condition was discovered in the Android binder driver, that could result in a use-after-free. On systems using this driver, a local user could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2020-8694

Multiple researchers discovered that the powercap subsystem allowed all users to read CPU energy meters, by default. On systems using Intel CPUs, this provided a side channel that could leak sensitive information between user processes, or from the kernel to user processes. The energy meters are now readable only by root, by default.

This issue can be mitigated by running:

chmod go-r /sys/devices/virtual/powercap/*/*/energy_uj

This needs to be repeated each time the system is booted with an unfixed kernel version.

CVE-2020-14351

A race condition was discovered in the performance events subsystem, which could lead to a use-after-free. A local user permitted to access performance events could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

Debian's kernel configuration does not allow unprivileged users to access performance events by default, which fully mitigates this issue.

CVE-2020-25656

Yuan Ming and Bodong Zhao discovered a race condition in the virtual terminal (vt) driver that could lead to a use-after-free. A local user with the CAP_SYS_TTY_CONFIG capability could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2020-25668

Yuan Ming and Bodong Zhao discovered a race condition in the virtual terminal (vt) driver that could lead to a use-after-free. A local user with access to a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-4.19' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-4.19", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.19", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-686-pae", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-686", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-all-amd64", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-all-arm64", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-all-armel", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-all-armhf", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-all-i386", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-all", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-amd64", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-arm64", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-armmp-lpae", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-armmp", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-cloud-amd64", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-common-rt", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-common", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-marvell", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-rpi", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-rt-686-pae", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-rt-amd64", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-rt-arm64", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.13-rt-armmp", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-686-dbg", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-686-pae-dbg", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-686-pae", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-686", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-amd64-dbg", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-amd64", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-arm64-dbg", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-arm64", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-armmp-dbg", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-armmp-lpae-dbg", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-armmp-lpae", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-armmp", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-cloud-amd64-dbg", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-cloud-amd64", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-marvell-dbg", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-marvell", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-rpi-dbg", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-rpi", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-rt-686-pae-dbg", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-rt-686-pae", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-rt-amd64-dbg", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-rt-amd64", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-rt-arm64-dbg", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-rt-arm64", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-rt-armmp-dbg", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.13-rt-armmp", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.19", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.19", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.19", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-0.bpo.13", ver:"4.19.160-2~deb9u1", rls:"DEB9"))) {
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
