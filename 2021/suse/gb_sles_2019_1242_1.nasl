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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1242.1");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-16880", "CVE-2019-11091", "CVE-2019-3882", "CVE-2019-9003", "CVE-2019-9500", "CVE-2019-9503");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-29 15:17:00 +0000 (Wed, 29 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1242-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1242-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191242-1/");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc/?id=7023736");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1242-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 Azure kernel was updated to receive various security and bugfixes.

Four new speculative execution information leak issues have been identified in Intel CPUs. (bsc#1111331)
CVE-2018-12126: Microarchitectural Store Buffer Data Sampling (MSBDS)

CVE-2018-12127: Microarchitectural Fill Buffer Data Sampling (MFBDS)

CVE-2018-12130: Microarchitectural Load Port Data Samling (MLPDS)

CVE-2019-11091: Microarchitectural Data Sampling Uncacheable Memory
 (MDSUM)

This kernel update contains software mitigations for these issues, which also utilize CPU microcode updates shipped in parallel.

For more information on this set of information leaks, check out [link moved to references]

The following security bugs were fixed:
CVE-2018-16880: A flaw was found in the handle_rx() function in the
 vhost_net driver. A malicious virtual guest, under specific conditions,
 could trigger an out-of-bounds write in a kmalloc-8 slab on a virtual
 host which may lead to a kernel memory corruption and a system panic.
 Due to the nature of the flaw, privilege escalation cannot be fully
 ruled out. (bnc#1122767).

CVE-2019-9003: Attackers could trigger a
 drivers/char/ipmi/ipmi_msghandler.c use-after-free and OOPS by arranging
 for certain simultaneous execution of the code, as demonstrated by a
 'service ipmievd restart' loop (bnc#1126704).

CVE-2019-9503: A brcmfmac frame validation bypass was fixed.
 (bnc#1132828).

CVE-2019-9500: A brcmfmac heap buffer overflow in brcmf_wowl_nd_results
 was fixed. (bnc#1132681).

CVE-2019-3882: A flaw was found in the vfio interface implementation
 that permitted violation of the user's locked memory limit. If a device
 is bound to a vfio driver, such as vfio-pci, and the local attacker is
 administratively granted ownership of the device, it may cause a system
 memory exhaustion and thus a denial of service (DoS). (bnc#1131416
 bnc#1131427).

The following non-security bugs were fixed:
9p: do not trust pdu content for stat item size (bsc#1051510).

acpi: acpi_pad: Do not launch acpi_pad threads on idle cpus
 (bsc#1113399).

acpi, nfit: Prefer _DSM over _LSR for namespace label reads (bsc#112128)
 (bsc#1132426).

acpi / sbs: Fix GPE storm on recent MacBookPro's (bsc#1051510).

alsa: core: Fix card races between register and disconnect (bsc#1051510).

alsa: echoaudio: add a check for ioremap_nocache (bsc#1051510).

alsa: firewire: add const qualifier to identifiers for read-only symbols
 (bsc#1051510).

alsa: firewire-motu: add a flag for AES/EBU on XLR interface
 (bsc#1051510).

alsa: firewire-motu: add specification flag for position of flag for
 MIDI messages (bsc#1051510).

alsa: firewire-motu: add support for MOTU Audio Express (bsc#1051510).

alsa: firewire-motu: add support for Motu Traveler (bsc#1051510).

alsa: firewire-motu: use 'version' field of unit directory to identify
 model ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~6.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~6.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~6.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~6.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~6.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~6.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~6.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~6.12.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~6.12.1", rls:"SLES12.0SP4"))) {
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
