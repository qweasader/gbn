# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1574.1");
  script_cve_id("CVE-2021-29155", "CVE-2021-29650");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-23 02:15:00 +0000 (Wed, 23 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1574-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1574-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211574-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:1574-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2021-29650: Fixed an issue with the netfilter subsystem that allowed
 attackers to cause a denial of service (panic) because
 net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h lack a
 full memory barrier upon the assignment of a new table value
 (bnc#1184208).

CVE-2021-29155: Fixed an issue that was discovered in
 kernel/bpf/verifier.c that performs undesirable out-of-bounds
 speculation on pointer arithmetic, leading to side-channel attacks that
 defeat Spectre mitigations and obtain sensitive information from kernel
 memory. Specifically, for sequences of pointer arithmetic operations,
 the pointer modification performed by the first operation was not
 correctly accounted for when restricting subsequent operations
 (bnc#1184942).

The following non-security bugs were fixed:

ACPI: CPPC: Replace cppc_attr with kobj_attribute (git-fixes).

ALSA: core: remove redundant spin_lock pair in snd_card_disconnect
 (git-fixes).

ALSA: emu8000: Fix a use after free in snd_emu8000_create_mixer
 (git-fixes).

ALSA: hda/cirrus: Add error handling into CS8409 I2C functions
 (git-fixes).

ALSA: hda/cirrus: Add Headphone and Headset MIC Volume Control
 (git-fixes).

ALSA: hda/cirrus: Add jack detect interrupt support from CS42L42
 companion codec (git-fixes).

ALSA: hda/cirrus: Add support for CS8409 HDA bridge and CS42L42
 companion codec (git-fixes).

ALSA: hda/cirrus: Cleanup patch_cirrus.c code (git-fixes).

ALSA: hda/cirrus: Fix CS42L42 Headset Mic volume control name
 (git-fixes).

ALSA: hda/cirrus: Make CS8409 driver more generic by using fixups
 (git-fixes).

ALSA: hda/cirrus: Set Initial DMIC volume for Bullseye to -26 dB
 (git-fixes).

ALSA: hda/cirrus: Use CS8409 filter to fix abnormal sounds on Bullseye
 (git-fixes).

ALSA: hda/realtek: Add quirk for Intel Clevo PCx0Dx (git-fixes).

ALSA: hda/realtek: fix mic boost on Intel NUC 8 (git-fixes).

ALSA: hda/realtek: fix static noise on ALC285 Lenovo laptops (git-fixes).

ALSA: hda/realtek: GA503 use same quirks as GA401 (git-fixes).

ALSA: hda/realtek - Headset Mic issue on HP platform (git-fixes).

ALSA: hda/realtek: Remove redundant entry for ALC861 Haier/Uniwill
 devices (git-fixes).

ALSA: hda/realtek: Re-order ALC269 Acer quirk table entries (git-fixes).

ALSA: hda/realtek: Re-order ALC269 ASUS quirk table entries (git-fixes).

ALSA: hda/realtek: Re-order ALC269 Dell quirk table entries (git-fixes).

ALSA: hda/realtek: Re-order ALC269 HP quirk table entries (git-fixes).

ALSA: hda/realtek: Re-order ALC269 Lenovo quirk table entries
 (git-fixes).

ALSA: hda/realtek: Re-order ALC269 Sony quirk table entries (git-fixes).

ALSA: hda/realtek: Re-order ALC662 quirk table entries (git-fixes).

ALSA: hda/realtek: Re-order ALC882 Acer quirk table entries (git-fixes).

ALSA: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Legacy Software 15-SP2, SUSE Linux Enterprise Module for Live Patching 15-SP2, SUSE Linux Enterprise Workstation Extension 15-SP2, SUSE MicroOS 5.0.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~24.64.1.9.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~24.64.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~24.64.1", rls:"SLES15.0SP2"))) {
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
