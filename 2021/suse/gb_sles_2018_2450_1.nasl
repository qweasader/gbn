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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2450.1");
  script_cve_id("CVE-2018-10853", "CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10881", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5391");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-12-30T10:12:19+0000");
  script_tag(name:"last_modification", value:"2022-12-30 10:12:19 +0000 (Fri, 30 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-28 18:07:00 +0000 (Wed, 28 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2450-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2450-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182450-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2450-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 azure kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2018-5391: A remote attacker even with relatively low bandwidth
 could have caused lots of CPU usage by triggering the worst case
 scenario during fragment reassembly (bsc#1103097)
- CVE-2018-3620, CVE-2018-3646: Local attackers in virtualized guest
 systems could use speculative code patterns on hyperthreaded processors
 to read data present in the L1 Datacache used by other hyperthreads on
 the same CPU core, potentially leaking sensitive data, even from other
 virtual machines or the host system. (bnc#1089343, bsc#1087081).
- CVE-2018-10882: A local user could have caused an out-of-bound write,
 leading to denial of service and a system crash by unmounting a crafted
 ext4 filesystem image (bsc#1099849).
- CVE-2018-10880: Prevent a stack-out-of-bounds write in the ext4
 filesystem code when mounting and writing crafted ext4 images. An
 attacker could have used this to cause a system crash and a denial of
 service (bsc#1099845).
- CVE-2018-10881: A local user could have caused an out-of-bound access
 and a system crash by mounting and operating on a crafted ext4
 filesystem image (bsc#1099864).
- CVE-2018-10877: Prevent an out-of-bound access in the
 ext4_ext_drop_refs() function when operating on a crafted ext4
 filesystem image (bsc#1099846).
- CVE-2018-10876: Prevent use-after-free in ext4_ext_remove_space()
 function when mounting and operating a crafted ext4 image (bsc#1099811).
- CVE-2018-10878: A local user could have caused an out-of-bounds write
 and a denial of service by mounting and operating a crafted ext4
 filesystem image (bsc#1099813).
- CVE-2018-10883: A local user could have caused an out-of-bounds write in
 jbd2_journal_dirty_metadata(), a denial of service, and a system crash
 by mounting and operating on a crafted ext4 filesystem image
 (bsc#1099863).
- CVE-2018-10879: A local user could have caused a use-after-free in
 ext4_xattr_set_entry function and a denial of service or unspecified
 other impact may occur by renaming a file in a crafted ext4 filesystem
 image (bsc#1099844).
- CVE-2018-10853: A flaw was found in Linux Kernel KVM. In which certain
 instructions such as sgdt/sidt call segmented_write_std doesn't
 propagate access correctly. As such, during userspace induced exception,
 the guest can incorrectly assume that the exception happened in the
 kernel and panic. (bnc#1097104).
The following non-security bugs were fixed:
- apci / lpss: Only call pwm_add_table() for Bay Trail PWM if PMIC HRV is
 2 (bsc#1051510).
- acpi / pci: Bail early in acpi_pci_add_bus() if there is no ACPI handle
 (bsc#1051510).
- af_key: Always verify length of provided sadb_key (bsc#1051510).
- af_key: fix buffer overread in parse_exthdrs() (bsc#1051510).
- af_key: fix buffer overread in verify_address_len() (bsc#1051510).
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~5.13.1", rls:"SLES15.0"))) {
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
