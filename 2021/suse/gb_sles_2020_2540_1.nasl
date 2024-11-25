# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2540.1");
  script_cve_id("CVE-2018-3639", "CVE-2020-14314", "CVE-2020-14331", "CVE-2020-14356", "CVE-2020-16166", "CVE-2020-1749", "CVE-2020-24394");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-25 19:17:14 +0000 (Tue, 25 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2540-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2540-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202540-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2540-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-1749: Use ip6_dst_lookup_flow instead of ip6_dst_lookup
 (bsc#1165629).

CVE-2020-14314: Fixed a potential negative array index in do_split()
 (bsc#1173798).

CVE-2020-14356: Fixed a null pointer dereference in cgroupv2 subsystem
 which could have led to privilege escalation (bsc#1175213).

CVE-2020-14331: Fixed a missing check in vgacon scrollback handling
 (bsc#1174205).

CVE-2020-16166: Fixed a potential issue which could have allowed remote
 attackers to make observations that help to obtain sensitive information
 about the internal state of the network RNG (bsc#1174757).

CVE-2020-24394: Fixed an issue which could set incorrect permissions on
 new filesystem objects when the filesystem lacks ACL support
 (bsc#1175518).

The following non-security bugs were fixed:

ACPI: kABI fixes for subsys exports (bsc#1174968).

ACPI / LPSS: Resume BYT/CHT I2C controllers from resume_noirq
 (bsc#1174968).

ACPI / LPSS: Use acpi_lpss_* instead of acpi_subsys_* functions for
 hibernate (bsc#1174968).

ACPI: PM: Introduce 'poweroff' callbacks for ACPI PM domain and LPSS
 (bsc#1174968).

ACPI: PM: Simplify and fix PM domain hibernation callbacks (bsc#1174968).

af_key: pfkey_dump needs parameter validation (git-fixes).

agp/intel: Fix a memory leak on module initialisation failure
 (git-fixes).

ALSA: core: pcm_iec958: fix kernel-doc (bsc#1111666).

ALSA: echoaduio: Drop superfluous volatile modifier (bsc#1111666).

ALSA: echoaudio: Fix potential Oops in snd_echo_resume() (bsc#1111666).

ALSA: hda: Add support for Loongson 7A1000 controller (bsc#1111666).

ALSA: hda/ca0132 - Add new quirk ID for Recon3D (bsc#1111666).

ALSA: hda/ca0132 - Fix AE-5 microphone selection commands (bsc#1111666).

ALSA: hda/ca0132 - Fix ZxR Headphone gain control get value
 (bsc#1111666).

ALSA: hda: fix NULL pointer dereference during suspend (git-fixes).

ALSA: hda: fix snd_hda_codec_cleanup() documentation (bsc#1111666).

ALSA: hda - fix the micmute led status for Lenovo ThinkCentre AIO
 (bsc#1111666).

ALSA: hda/realtek: Add alc269/alc662 pin-tables for Loongson-3 laptops
 (bsc#1111666).

ALSA: hda/realtek: Add model alc298-samsung-headphone (git-fixes).

ALSA: hda/realtek: Add mute LED and micmute LED support for HP systems
 (bsc#1111666).

ALSA: hda/realtek - Add quirk for Lenovo Carbon X1 8th gen (bsc#1111666).

ALSA: hda/realtek - Add quirk for MSI GE63 laptop (bsc#1111666).

ALSA: hda/realtek - Add quirk for MSI GL63 (bsc#1111666).

ALSA: hda/realtek: Add quirk for Samsung Galaxy Book Ion (git-fixes).

ALSA: hda/realtek: Add quirk for Samsung Galaxy Flex Book (git-fixes).

ALSA: hda/realtek - change to suitable link model for ASUS platform
 (bsc#1111666).

ALSA: hda/realtek - Check headset type by unplug and resume
 (bsc#1111666).

ALSA: hda/realtek ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.25.1", rls:"SLES12.0SP5"))) {
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
