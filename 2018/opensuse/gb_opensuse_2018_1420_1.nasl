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
  script_oid("1.3.6.1.4.1.25623.1.0.851999");
  script_version("2021-06-29T11:00:37+0000");
  script_cve_id("CVE-2018-3639");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-06-29 11:00:37 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 14:51:00 +0000 (Wed, 14 Apr 2021)");
  script_tag(name:"creation_date", value:"2018-10-26 06:33:17 +0200 (Fri, 26 Oct 2018)");
  script_name("openSUSE: Security Advisory for kernel (openSUSE-SU-2018:1420-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:1420-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-05/msg00101.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the openSUSE-SU-2018:1420-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The openSUSE Leap 15.0 kernel was updated to
  receive various security and bugfixes.

  The following security bugs were fixed:

  - CVE-2018-3639: Systems with microprocessors utilizing speculative
  execution and speculative execution of memory reads before the addresses
  of all prior memory writes are known may allow unauthorized disclosure
  of information to an attacker with local user access via a side-channel
  analysis, aka Speculative Store Bypass (SSB), Variant 4 (bsc#1087082).

  A new boot commandline option was introduced,
  'spec_store_bypass_disable', which can have following values:

  - auto: Kernel detects whether your CPU model contains an implementation
  of Speculative Store Bypass and picks the most appropriate mitigation.

  - on: disable Speculative Store Bypass

  - off: enable Speculative Store Bypass

  - prctl: Control Speculative Store Bypass per thread via prctl.
  Speculative Store Bypass is enabled for a process by default. The
  state of the control is inherited on fork.

  - seccomp: Same as 'prctl' above, but all seccomp threads will disable
  SSB unless they explicitly opt out.

  The default is 'seccomp', meaning programs need explicit opt-in into the
  mitigation.

  Status can be queried via the
  /sys/devices/system/cpu/vulnerabilities/spec_store_bypass file, containing:

  - 'Vulnerable'

  - 'Mitigation: Speculative Store Bypass disabled'

  - 'Mitigation: Speculative Store Bypass disabled via prctl'

  - 'Mitigation: Speculative Store Bypass disabled via prctl and seccomp'

  The following non-security bugs were fixed:

  - allow_unsupported: add module tainting on feature use (FATE#323394).

  - powerpc/64/kexec: fix race in kexec when XIVE is shutdown (bsc#1088273).

  - reiserfs: mark read-write mode unsupported (FATE#323394).

  - reiserfs: package in separate KMP (FATE#323394).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-515=1");

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
  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base-debuginfo", rpm:"kernel-debug-base-debuginfo~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-base", rpm:"kernel-kvmsmall-base~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-base-debuginfo", rpm:"kernel-kvmsmall-base-debuginfo~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debuginfo", rpm:"kernel-kvmsmall-debuginfo~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debugsource", rpm:"kernel-kvmsmall-debugsource~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel-debuginfo", rpm:"kernel-kvmsmall-devel-debuginfo~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~4.12.14~lp150.12.4.1", rls:"openSUSELeap15.0"))) {
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
