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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1537.1");
  script_cve_id("CVE-2017-13166", "CVE-2018-8781", "CVE-2018-8897");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1537-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1537-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181537-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 23 for SLE 12 SP1)' package(s) announced via the SUSE-SU-2018:1537-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 3.12.74-60_64_66 fixes several issues.
The following security issues were fixed:
- CVE-2017-13166: An elevation of privilege vulnerability in the kernel
 v4l2 video driver was fixed. (bsc#1085447).
- CVE-2018-8897: A statement in the System Programming Guide of the Intel
 64 and IA-32 Architectures Software Developer's Manual (SDM) was
 mishandled in the development of some or all operating-system kernels,
 resulting in unexpected behavior for #DB exceptions that are deferred by
 MOV SS or POP SS, as demonstrated by (for example) privilege escalation
 in Windows, macOS, some Xen configurations, or FreeBSD, or a Linux
 kernel crash. The MOV to SS and POP SS instructions inhibit interrupts
 (including NMIs), data breakpoints, and single step trap exceptions
 until the instruction boundary following the next instruction (SDM Vol.
 3A, section 6.8.3). (The inhibited data breakpoints are those on memory
 accessed by the MOV to SS or POP to SS instruction itself.) Note that
 debug exceptions are not inhibited by the interrupt enable (EFLAGS.IF)
 system flag (SDM Vol. 3A, section 2.3). If the instruction following the
 MOV to SS or POP to SS instruction is an instruction like SYSCALL,
 SYSENTER, INT 3, etc. that transfers control to the operating system at
 CPL
 is complete. OS kernels may not expect this order of events and may
 therefore experience unexpected behavior when it occurs (bsc#1090368).
- CVE-2018-8781: The udl_fb_mmap function in drivers/gpu/drm/udl/udl_fb.c
 had an integer-overflow vulnerability allowing local users with access
 to the udldrmfb driver to obtain full read and write permissions on
 kernel physical pages, resulting in a code execution in kernel space
 (bsc#1090646).
- bsc#1083125: Fixed kgraft: small race in reversion code");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 23 for SLE 12 SP1)' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_66-default", rpm:"kgraft-patch-3_12_74-60_64_66-default~5~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_66-xen", rpm:"kgraft-patch-3_12_74-60_64_66-xen~5~2.1", rls:"SLES12.0SP1"))) {
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
