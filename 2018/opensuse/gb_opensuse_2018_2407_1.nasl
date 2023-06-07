# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851952");
  script_version("2022-12-30T10:12:19+0000");
  script_cve_id("CVE-2018-10853", "CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10881", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5391");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-12-30 10:12:19 +0000 (Fri, 30 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-28 18:07:00 +0000 (Wed, 28 Dec 2022)");
  script_tag(name:"creation_date", value:"2018-10-26 06:21:47 +0200 (Fri, 26 Oct 2018)");
  script_name("openSUSE: Security Advisory for kernel (openSUSE-SU-2018:2407-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:2407-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00064.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the openSUSE-SU-2018:2407-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The openSUSE Leap 15.0 kernel was updated to receive various security and
  bugfixes.

  The following security bugs were fixed:

  - CVE-2018-10853: A flaw was found in KVM in which certain instructions
  such as sgdt/sidt call segmented_write_std doesn't propagate access
  correctly. As such, during userspace induced exception, the guest can
  incorrectly assume that the exception happened in the kernel and panic
  (bnc#1097104).

  - CVE-2018-10876: A flaw was found in the ext4 filesystem code. A
  use-after-free is possible in ext4_ext_remove_space() function when
  mounting and operating a crafted ext4 image. (bnc#1099811)

  - CVE-2018-10877: Linux kernel ext4 filesystem is vulnerable to an
  out-of-bound access in the ext4_ext_drop_refs() function when operating
  on a crafted ext4 filesystem image. (bnc#1099846)

  - CVE-2018-10878: A flaw was found in the ext4 filesystem. A local user
  can cause an out-of-bounds write and a denial of service or unspecified
  other impact is possible by mounting and operating a crafted ext4
  filesystem image. (bnc#1099813)

  - CVE-2018-10879: A flaw was found in the ext4 filesystem. A local user
  can cause a use-after-free in ext4_xattr_set_entry function and a denial
  of service or unspecified other impact may occur by renaming a file in a
  crafted ext4 filesystem image. (bnc#1099844)

  - CVE-2018-10880: Linux kernel is vulnerable to a stack-out-of-bounds
  write in the ext4 filesystem code when mounting and writing to a crafted
  ext4 image in ext4_update_inline_data(). An attacker could use this to
  cause a system crash and a denial of service. (bnc#1099845)

  - CVE-2018-10881: A flaw was found in the ext4 filesystem. A local user
  can cause an out-of-bound access in ext4_get_group_info function, a
  denial of service, and a system crash by mounting and operating on a
  crafted ext4 filesystem image. (bnc#1099864)

  - CVE-2018-10882: A flaw was found in the ext4 filesystem. A local user
  can cause an out-of-bound write in fs/jbd2/transaction.c code, a
  denial of service, and a system crash by unmounting a crafted ext4
  filesystem image. (bnc#1099849)

  - CVE-2018-10883: A flaw was found in the ext4 filesystem. A local user
  can cause an out-of-bounds write in jbd2_journal_dirty_metadata(), a
  denial of service, and a system crash by mounting and operating on a
  crafted ext4 filesystem image. (bnc#1099863)

  - CVE-2018-3620: Systems with microprocessors utilizing speculative
  execution and address translations may allow unauthorized disclosure of
  information residing in the L1 data cache to an attacker with local user
  access  ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"the on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base-debuginfo", rpm:"kernel-debug-base-debuginfo~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-base", rpm:"kernel-kvmsmall-base~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-base-debuginfo", rpm:"kernel-kvmsmall-base-debuginfo~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debuginfo", rpm:"kernel-kvmsmall-debuginfo~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debugsource", rpm:"kernel-kvmsmall-debugsource~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel-debuginfo", rpm:"kernel-kvmsmall-devel-debuginfo~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-devel-debuginfo", rpm:"kernel-vanilla-devel-debuginfo~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~4.12.14~lp150.12.16.1", rls:"openSUSELeap15.0"))) {
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
