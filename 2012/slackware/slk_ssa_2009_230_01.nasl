# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.64771");
  script_cve_id("CVE-2009-2692");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2022-08-23T10:11:31+0000");
  script_tag(name:"last_modification", value:"2022-08-23 10:11:31 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2009-230-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(12\.1|12\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2009-230-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.877234");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2009-230-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New Linux kernel packages are available for Slackware 12.2 and -current
to address a security issue. A kernel bug discovered by Tavis Ormandy
and Julien Tinnes of the Google Security Team could allow a local user
to fill memory page zero with arbitrary code and then use the kernel
sendpage operation to trigger a NULL pointer dereference, executing the
code in the context of the kernel. If successfully exploited, this bug
can be used to gain root access.

At this time we have prepared fixed kernels for the stable version of
Slackware (12.2), as well as for both 32-bit x86 and x86_64 -current
versions. Additionally, we have added a package to the /patches
directory for Slackware 12.1 and 12.2 that will set the minimum memory
page that can be mmap()ed from userspace without additional privileges
to 4096. The package will work with any kernel supporting the
vm.mmap_min_addr tunable, and should significantly reduce the potential
harm from this bug, as well as future similar bugs that might be found
in the kernel. More updated kernels may follow.

For more information, see:
 [link moved to references]


Here are the details from the Slackware 12.2 ChangeLog:
+--------------------------+
patches/packages/linux-2.6.27.31/:
 Added new kernels and kernel packages for Linux 2.6.27.31 to address
 a bug in proto_ops structures which could allow a user to use the
 kernel sendpage operation to execute arbitrary code in page zero.
 This could allow local users to gain escalated privileges.
 This flaw was discovered by Tavis Ormandy and Julien Tinnes of the
 Google Security Team.
 For more information, see:
 [link moved to references]
 In addition, these kernels change CONFIG_DEFAULT_MMAP_MIN_ADDR kernel
 config option value to 4096, which should prevent the execution of
 arbitrary code by future NULL dereference bugs that might be found in
 the kernel. If you are compiling your own kernel, please check this
 option in your .config. If it is set to =0, you may wish to edit it
 to 4096 (or some other value > 0) and then reconfigure, or the kernel
 will not have default protection against zero page attacks from
 userspace.
 (* Security fix *)
patches/packages/kernel-mmap_min_addr-4096-noarch-1.tgz:
 This package adds an init script to edit /etc/sysctl.conf, adding
 this config option:
 vm.mmap_min_addr = 4096
 This will configure the kernel to disallow mmap() to userspace of any
 page lower than 4096, preventing privilege escalation by CVE-2009-2692.
 This is a hot fix package and will take effect immediately upon
 installation on any system running a kernel that supports configurable
 /proc/sys/vm/mmap_min_addr (kernel 2.6.23 or newer).
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'kernel' package(s) on Slackware 12.1, Slackware 12.2, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK12.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-mmap_min_addr", ver:"4096-noarch-1", rls:"SLK12.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-firmware", ver:"2.6.27.31-noarch-1", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"2.6.27.31-i486-1", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"2.6.27.31_smp-i686-1", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"2.6.27.31_smp-x86-1", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"2.6.27.31-i486-1", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"2.6.27.31_smp-i686-1", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-mmap_min_addr", ver:"4096-noarch-1", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"2.6.27.31-i486-1", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"2.6.27.31_smp-i686-1", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.6.27.31_smp-noarch-1", rls:"SLK12.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-firmware", ver:"2.6.29.6-noarch-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-firmware", ver:"2.6.29.6-noarch-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"2.6.29.6-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"2.6.29.6-x86_64-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"2.6.29.6_smp-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"2.6.29.6-x86-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"2.6.29.6_smp-x86-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"2.6.29.6-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"2.6.29.6-x86_64-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"2.6.29.6_smp-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"2.6.29.6-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"2.6.29.6-x86_64-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"2.6.29.6_smp-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.6.29.6-noarch-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.6.29.6_smp-noarch-1", rls:"SLKcurrent"))) {
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
