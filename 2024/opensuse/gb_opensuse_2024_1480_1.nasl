# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856120");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2021-46925", "CVE-2021-46926", "CVE-2021-46927", "CVE-2021-46929", "CVE-2021-46930", "CVE-2021-46931", "CVE-2021-46933", "CVE-2021-46934", "CVE-2021-46936", "CVE-2021-47082", "CVE-2021-47083", "CVE-2021-47087", "CVE-2021-47091", "CVE-2021-47093", "CVE-2021-47094", "CVE-2021-47095", "CVE-2021-47096", "CVE-2021-47097", "CVE-2021-47098", "CVE-2021-47099", "CVE-2021-47100", "CVE-2021-47101", "CVE-2021-47102", "CVE-2021-47104", "CVE-2021-47105", "CVE-2021-47107", "CVE-2021-47108", "CVE-2022-4744", "CVE-2022-48626", "CVE-2022-48627", "CVE-2022-48628", "CVE-2022-48629", "CVE-2022-48630", "CVE-2023-0160", "CVE-2023-28746", "CVE-2023-35827", "CVE-2023-4881", "CVE-2023-52447", "CVE-2023-52450", "CVE-2023-52453", "CVE-2023-52454", "CVE-2023-52462", "CVE-2023-52463", "CVE-2023-52467", "CVE-2023-52469", "CVE-2023-52470", "CVE-2023-52474", "CVE-2023-52476", "CVE-2023-52477", "CVE-2023-52481", "CVE-2023-52482", "CVE-2023-52484", "CVE-2023-52486", "CVE-2023-52492", "CVE-2023-52493", "CVE-2023-52494", "CVE-2023-52497", "CVE-2023-52500", "CVE-2023-52501", "CVE-2023-52502", "CVE-2023-52504", "CVE-2023-52507", "CVE-2023-52508", "CVE-2023-52509", "CVE-2023-52510", "CVE-2023-52511", "CVE-2023-52513", "CVE-2023-52515", "CVE-2023-52517", "CVE-2023-52518", "CVE-2023-52519", "CVE-2023-52520", "CVE-2023-52523", "CVE-2023-52524", "CVE-2023-52525", "CVE-2023-52528", "CVE-2023-52529", "CVE-2023-52530", "CVE-2023-52531", "CVE-2023-52532", "CVE-2023-52559", "CVE-2023-52563", "CVE-2023-52564", "CVE-2023-52566", "CVE-2023-52567", "CVE-2023-52569", "CVE-2023-52574", "CVE-2023-52575", "CVE-2023-52576", "CVE-2023-52582", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52591", "CVE-2023-52594", "CVE-2023-52595", "CVE-2023-52597", "CVE-2023-52598", "CVE-2023-52599", "CVE-2023-52600", "CVE-2023-52601", "CVE-2023-52602", "CVE-2023-52603", "CVE-2023-52604", "CVE-2023-52605", "CVE-2023-52606", "CVE-2023-52607", "CVE-2023-52608", "CVE-2023-52612", "CVE-2023-52615", "CVE-2023-52617", "CVE-2023-52619", "CVE-2023-52621", "CVE-2023-52623", "CVE-2023-52628", "CVE-2023-52632", "CVE-2023-52637", "CVE-2023-52639", "CVE-2023-6270", "CVE-2023-6356", "CVE-2023-6535", "CVE-2023-6536", "CVE-2023-7042", "CVE-2023-7192", "CVE-2024-0841", "CVE-2024-2201", "CVE-2024-22099", "CVE-2024-23307", "CVE-2024-25739", "CVE-2024-25742", "CVE-2024-25743", "CVE-2024-26599", "CVE-2024-26600", "CVE-2024-26602", "CVE-2024-26607", "CVE-2024-26612", "CVE-2024-26614", "CVE-2024-26620", "CVE-2024-26627", "CVE-2024-26629", "CVE-2024-26642", "CVE-2024-26645", "CVE-2024-26646", "CVE-2024-26651", "CVE-2024-26654", "CVE-2024-26659", "CVE-2024-26664", "CVE-2024-26667", "CVE-2024-26670", "CVE-2024-26695", "CVE-2024-26717");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-17 19:34:01 +0000 (Wed, 17 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-05-07 01:05:55 +0000 (Tue, 07 May 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:1480-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1480-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SC25JPS3E5RSHU4LE76Y2D5PU4MP3LKJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:1480-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2021-46925: Fixed kernel panic caused by race of smc_sock (bsc#1220466).

  * CVE-2021-46926: Fixed bug when detecting controllers in ALSA/hda/intel-sdw-
      acpi (bsc#1220478).

  * CVE-2021-46927: Fixed assertion bug in nitro_enclaves: Use
      get_user_pages_unlocked() (bsc#1220443).

  * CVE-2021-46929: Fixed use-after-free issue in sctp_sock_dump()
      (bsc#1220482).

  * CVE-2021-46930: Fixed usb/mtu3 list_head check warning (bsc#1220484).

  * CVE-2021-46931: Fixed wrong type casting in mlx5e_tx_reporter_dump_sq()
      (bsc#1220486).

  * CVE-2021-46933: Fixed possible underflow in ffs_data_clear() (bsc#1220487).

  * CVE-2021-46934: Fixed a bug by validating user data in compat ioctl
      (bsc#1220469).

  * CVE-2021-46936: Fixed use-after-free in tw_timer_handler() (bsc#1220439).

  * CVE-2021-47082: Fixed ouble free in tun_free_netdev() (bsc#1220969).

  * CVE-2021-47083: Fixed a global-out-of-bounds issue in mediatek:
      (bsc#1220917).

  * CVE-2021-47087: Fixed incorrect page free bug in tee/optee (bsc#1220954).

  * CVE-2021-47091: Fixed locking in ieee80211_start_ap()) error path
      (bsc#1220959).

  * CVE-2021-47093: Fixed memleak on registration failure in intel_pmc_core
      (bsc#1220978).

  * CVE-2021-47094: Fixed possible memory leak in KVM x86/mmu (bsc#1221551).

  * CVE-2021-47095: Fixed missing initialization in ipmi/ssif (bsc#1220979).

  * CVE-2021-47096: Fixed uninitialized user_pversion in ALSA rawmidi
      (bsc#1220981).

  * CVE-2021-47097: Fixed stack out of bound access in
      elantech_change_report_id() (bsc#1220982).

  * CVE-2021-47098: Fixed integer overflow/underflow in hysteresis calculations
      hwmon: (lm90) (bsc#1220983).

  * CVE-2021-47099: Fixed BUG_ON assertion in veth when skb entering GRO are
      cloned (bsc#1220955).

  * CVE-2021-47100: Fixed UAF when uninstall in ipmi (bsc#1220985).

  * CVE-2021-47101: Fixed uninit-value in asix_mdio_read() (bsc#1220987).

  * CVE-2021-47102: Fixed incorrect structure access In line: upper =
      info->upper_dev in net/marvell/prestera (bsc#1221009).

  * CVE-2021-47104: Fixed memory leak in qib_user_sdma_queue_pkts()
      (bsc#1220960).

  * CVE-2021-47105: Fixed potential memory leak in ice/xsk (bsc#1220961).

  * CVE-2021-47107: Fixed READDIR buffer overflow in NFSD (bsc#1220965).

  * CVE-2021-47108: Fixed possible NULL pointer dereference for mtk_hdmi_conf in
      drm/mediatek (bsc#1220986).
    ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-livepatch-devel", rpm:"kernel-debug-livepatch-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso-debuginfo", rpm:"kernel-default-vdso-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso", rpm:"kernel-kvmsmall-vdso~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-vdso", rpm:"kernel-debug-vdso~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso", rpm:"kernel-default-vdso~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso-debuginfo", rpm:"kernel-kvmsmall-vdso-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-vdso-debuginfo", rpm:"kernel-debug-vdso-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150500.55.59.1.150500.6.25.7", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-livepatch-devel", rpm:"kernel-kvmsmall-livepatch-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debugsource", rpm:"kernel-kvmsmall-debugsource~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel-debuginfo", rpm:"kernel-kvmsmall-devel-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-rebuild", rpm:"kernel-default-base-rebuild~5.14.21~150500.55.59.1.150500.6.25.7", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debuginfo", rpm:"kernel-kvmsmall-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default-debuginfo", rpm:"gfs2-kmp-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional-debuginfo", rpm:"kernel-default-optional-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default", rpm:"kselftests-kmp-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional", rpm:"kernel-default-optional~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default-debuginfo", rpm:"dlm-kmp-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default-debuginfo", rpm:"ocfs2-kmp-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default-debuginfo", rpm:"kselftests-kmp-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default-debuginfo", rpm:"cluster-md-kmp-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra-debuginfo", rpm:"kernel-default-extra-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch-devel", rpm:"kernel-default-livepatch-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_55_59-default-debuginfo-1", rpm:"kernel-livepatch-5_14_21-150500_55_59-default-debuginfo-1~150500.11.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_55_59-default-1", rpm:"kernel-livepatch-5_14_21-150500_55_59-default-1~150500.11.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP5_Update_12-debugsource-1", rpm:"kernel-livepatch-SLE15-SP5_Update_12-debugsource-1~150500.11.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-aarch64", rpm:"dtb-aarch64~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb", rpm:"dlm-kmp-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-sprd", rpm:"dtb-sprd~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-qcom", rpm:"dtb-qcom~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-socionext", rpm:"dtb-socionext~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb-debuginfo", rpm:"reiserfs-kmp-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-allwinner", rpm:"dtb-allwinner~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-nvidia", rpm:"dtb-nvidia~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-lg", rpm:"dtb-lg~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb", rpm:"reiserfs-kmp-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-exynos", rpm:"dtb-exynos~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb", rpm:"kselftests-kmp-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel-debuginfo", rpm:"kernel-64kb-devel-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debugsource", rpm:"kernel-64kb-debugsource~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apm", rpm:"dtb-apm~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amlogic", rpm:"dtb-amlogic~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra-debuginfo", rpm:"kernel-64kb-extra-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb-debuginfo", rpm:"cluster-md-kmp-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb-debuginfo", rpm:"ocfs2-kmp-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb-debuginfo", rpm:"dlm-kmp-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-freescale", rpm:"dtb-freescale~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-arm", rpm:"dtb-arm~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-marvell", rpm:"dtb-marvell~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-hisilicon", rpm:"dtb-hisilicon~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-cavium", rpm:"dtb-cavium~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional", rpm:"kernel-64kb-optional~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional-debuginfo", rpm:"kernel-64kb-optional-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb-debuginfo", rpm:"kselftests-kmp-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debuginfo", rpm:"kernel-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb-debuginfo", rpm:"gfs2-kmp-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-livepatch-devel", rpm:"kernel-64kb-livepatch-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-rockchip", rpm:"dtb-rockchip~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-altera", rpm:"dtb-altera~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-broadcom", rpm:"dtb-broadcom~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amd", rpm:"dtb-amd~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-xilinx", rpm:"dtb-xilinx~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amazon", rpm:"dtb-amazon~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb", rpm:"ocfs2-kmp-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb", rpm:"gfs2-kmp-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-mediatek", rpm:"dtb-mediatek~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-renesas", rpm:"dtb-renesas~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb", rpm:"cluster-md-kmp-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apple", rpm:"dtb-apple~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-livepatch-devel", rpm:"kernel-debug-livepatch-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso-debuginfo", rpm:"kernel-default-vdso-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso", rpm:"kernel-kvmsmall-vdso~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-vdso", rpm:"kernel-debug-vdso~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso", rpm:"kernel-default-vdso~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso-debuginfo", rpm:"kernel-kvmsmall-vdso-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-vdso-debuginfo", rpm:"kernel-debug-vdso-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150500.55.59.1.150500.6.25.7", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-livepatch-devel", rpm:"kernel-kvmsmall-livepatch-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debugsource", rpm:"kernel-kvmsmall-debugsource~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel-debuginfo", rpm:"kernel-kvmsmall-devel-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-rebuild", rpm:"kernel-default-base-rebuild~5.14.21~150500.55.59.1.150500.6.25.7", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debuginfo", rpm:"kernel-kvmsmall-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default-debuginfo", rpm:"gfs2-kmp-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional-debuginfo", rpm:"kernel-default-optional-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default", rpm:"kselftests-kmp-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional", rpm:"kernel-default-optional~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default-debuginfo", rpm:"dlm-kmp-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default-debuginfo", rpm:"ocfs2-kmp-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default-debuginfo", rpm:"kselftests-kmp-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default-debuginfo", rpm:"cluster-md-kmp-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra-debuginfo", rpm:"kernel-default-extra-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch-devel", rpm:"kernel-default-livepatch-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_55_59-default-debuginfo-1", rpm:"kernel-livepatch-5_14_21-150500_55_59-default-debuginfo-1~150500.11.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_55_59-default-1", rpm:"kernel-livepatch-5_14_21-150500_55_59-default-1~150500.11.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP5_Update_12-debugsource-1", rpm:"kernel-livepatch-SLE15-SP5_Update_12-debugsource-1~150500.11.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-aarch64", rpm:"dtb-aarch64~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb", rpm:"dlm-kmp-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-sprd", rpm:"dtb-sprd~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-qcom", rpm:"dtb-qcom~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-socionext", rpm:"dtb-socionext~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb-debuginfo", rpm:"reiserfs-kmp-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-allwinner", rpm:"dtb-allwinner~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-nvidia", rpm:"dtb-nvidia~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-lg", rpm:"dtb-lg~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb", rpm:"reiserfs-kmp-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-exynos", rpm:"dtb-exynos~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb", rpm:"kselftests-kmp-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel-debuginfo", rpm:"kernel-64kb-devel-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debugsource", rpm:"kernel-64kb-debugsource~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apm", rpm:"dtb-apm~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amlogic", rpm:"dtb-amlogic~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra-debuginfo", rpm:"kernel-64kb-extra-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb-debuginfo", rpm:"cluster-md-kmp-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb-debuginfo", rpm:"ocfs2-kmp-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb-debuginfo", rpm:"dlm-kmp-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-freescale", rpm:"dtb-freescale~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-arm", rpm:"dtb-arm~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-marvell", rpm:"dtb-marvell~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-hisilicon", rpm:"dtb-hisilicon~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-cavium", rpm:"dtb-cavium~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional", rpm:"kernel-64kb-optional~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional-debuginfo", rpm:"kernel-64kb-optional-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb-debuginfo", rpm:"kselftests-kmp-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debuginfo", rpm:"kernel-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb-debuginfo", rpm:"gfs2-kmp-64kb-debuginfo~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-livepatch-devel", rpm:"kernel-64kb-livepatch-devel~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-rockchip", rpm:"dtb-rockchip~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-altera", rpm:"dtb-altera~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-broadcom", rpm:"dtb-broadcom~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amd", rpm:"dtb-amd~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-xilinx", rpm:"dtb-xilinx~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amazon", rpm:"dtb-amazon~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb", rpm:"ocfs2-kmp-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb", rpm:"gfs2-kmp-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-mediatek", rpm:"dtb-mediatek~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-renesas", rpm:"dtb-renesas~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb", rpm:"cluster-md-kmp-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apple", rpm:"dtb-apple~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150500.55.59.1", rls:"openSUSELeap15.5"))) {
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
