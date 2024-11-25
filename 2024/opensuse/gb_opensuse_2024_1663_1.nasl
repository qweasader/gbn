# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856379");
  script_version("2024-08-23T05:05:37+0000");
  script_cve_id("CVE-2021-47047", "CVE-2021-47181", "CVE-2021-47182", "CVE-2021-47183", "CVE-2021-47184", "CVE-2021-47185", "CVE-2021-47187", "CVE-2021-47188", "CVE-2021-47189", "CVE-2021-47191", "CVE-2021-47192", "CVE-2021-47193", "CVE-2021-47194", "CVE-2021-47195", "CVE-2021-47196", "CVE-2021-47197", "CVE-2021-47198", "CVE-2021-47199", "CVE-2021-47200", "CVE-2021-47201", "CVE-2021-47202", "CVE-2021-47203", "CVE-2021-47204", "CVE-2021-47205", "CVE-2021-47206", "CVE-2021-47207", "CVE-2021-47209", "CVE-2021-47210", "CVE-2021-47211", "CVE-2021-47212", "CVE-2021-47214", "CVE-2021-47215", "CVE-2021-47216", "CVE-2021-47217", "CVE-2021-47218", "CVE-2021-47219", "CVE-2022-48631", "CVE-2022-48632", "CVE-2022-48634", "CVE-2022-48636", "CVE-2022-48637", "CVE-2022-48638", "CVE-2022-48639", "CVE-2022-48640", "CVE-2022-48642", "CVE-2022-48644", "CVE-2022-48646", "CVE-2022-48647", "CVE-2022-48648", "CVE-2022-48650", "CVE-2022-48651", "CVE-2022-48652", "CVE-2022-48653", "CVE-2022-48654", "CVE-2022-48655", "CVE-2022-48656", "CVE-2022-48657", "CVE-2022-48658", "CVE-2022-48659", "CVE-2022-48660", "CVE-2022-48662", "CVE-2022-48663", "CVE-2022-48667", "CVE-2022-48668", "CVE-2022-48671", "CVE-2022-48672", "CVE-2022-48673", "CVE-2022-48675", "CVE-2022-48686", "CVE-2022-48687", "CVE-2022-48688", "CVE-2022-48690", "CVE-2022-48692", "CVE-2022-48693", "CVE-2022-48694", "CVE-2022-48695", "CVE-2022-48697", "CVE-2022-48698", "CVE-2022-48700", "CVE-2022-48701", "CVE-2022-48702", "CVE-2022-48703", "CVE-2022-48704", "CVE-2023-2860", "CVE-2023-52488", "CVE-2023-52503", "CVE-2023-52561", "CVE-2023-52585", "CVE-2023-52589", "CVE-2023-52590", "CVE-2023-52591", "CVE-2023-52593", "CVE-2023-52614", "CVE-2023-52616", "CVE-2023-52620", "CVE-2023-52627", "CVE-2023-52635", "CVE-2023-52636", "CVE-2023-52645", "CVE-2023-52652", "CVE-2023-6270", "CVE-2024-0639", "CVE-2024-0841", "CVE-2024-22099", "CVE-2024-23307", "CVE-2024-23848", "CVE-2024-23850", "CVE-2024-26601", "CVE-2024-26610", "CVE-2024-26656", "CVE-2024-26660", "CVE-2024-26671", "CVE-2024-26673", "CVE-2024-26675", "CVE-2024-26680", "CVE-2024-26681", "CVE-2024-26684", "CVE-2024-26685", "CVE-2024-26687", "CVE-2024-26688", "CVE-2024-26689", "CVE-2024-26696", "CVE-2024-26697", "CVE-2024-26702", "CVE-2024-26704", "CVE-2024-26718", "CVE-2024-26722", "CVE-2024-26727", "CVE-2024-26733", "CVE-2024-26736", "CVE-2024-26737", "CVE-2024-26739", "CVE-2024-26743", "CVE-2024-26744", "CVE-2024-26745", "CVE-2024-26747", "CVE-2024-26749", "CVE-2024-26751", "CVE-2024-26754", "CVE-2024-26760", "CVE-2024-267600", "CVE-2024-26763", "CVE-2024-26764", "CVE-2024-26766", "CVE-2024-26769", "CVE-2024-26771", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26776", "CVE-2024-26779", "CVE-2024-26783", "CVE-2024-26787", "CVE-2024-26790", "CVE-2024-26792", "CVE-2024-26793", "CVE-2024-26798", "CVE-2024-26805", "CVE-2024-26807", "CVE-2024-26816", "CVE-2024-26817", "CVE-2024-26820", "CVE-2024-26825", "CVE-2024-26830", "CVE-2024-26833", "CVE-2024-26836", "CVE-2024-26843", "CVE-2024-26848", "CVE-2024-26852", "CVE-2024-26853", "CVE-2024-26855", "CVE-2024-26856", "CVE-2024-26857", "CVE-2024-26861", "CVE-2024-26862", "CVE-2024-26866", "CVE-2024-26872", "CVE-2024-26875", "CVE-2024-26878", "CVE-2024-26879", "CVE-2024-26881", "CVE-2024-26882", "CVE-2024-26883", "CVE-2024-26884", "CVE-2024-26885", "CVE-2024-26891", "CVE-2024-26893", "CVE-2024-26895", "CVE-2024-26896", "CVE-2024-26897", "CVE-2024-26898", "CVE-2024-26901", "CVE-2024-26903", "CVE-2024-26917", "CVE-2024-26927", "CVE-2024-26948", "CVE-2024-26950", "CVE-2024-26951", "CVE-2024-26955", "CVE-2024-26956", "CVE-2024-26960", "CVE-2024-26965", "CVE-2024-26966", "CVE-2024-26969", "CVE-2024-26970", "CVE-2024-26972", "CVE-2024-26981", "CVE-2024-26982", "CVE-2024-26993", "CVE-2024-27013", "CVE-2024-27014", "CVE-2024-27030", "CVE-2024-27038", "CVE-2024-27039", "CVE-2024-27041", "CVE-2024-27043", "CVE-2024-27046", "CVE-2024-27056", "CVE-2024-27062", "CVE-2024-27389");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-29 19:31:26 +0000 (Mon, 29 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 04:08:54 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:1663-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1663-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MFQEXBT2XPZQJMUF7MN6ZVO5FXVY4NKK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:1663-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 Real Time kernel was updated to receive various
  security bugfixes.

  The following security bugs were fixed:

  * CVE-2024-27389: Fixed pstore inode handling with d_invalidate()
      (bsc#1223705).

  * CVE-2024-27062: Fixed nouveau lock inside client object tree (bsc#1223834).

  * CVE-2024-27056: Fixed wifi/iwlwifi/mvm to ensure offloading TID queue exists
      (bsc#1223822).

  * CVE-2024-27046: Fixed nfp/flower handling acti_netdevs allocation failure
      (bsc#1223827).

  * CVE-2024-27043: Fixed a use-after-free in edia/dvbdev in different places
      (bsc#1223824).

  * CVE-2024-27041: Fixed drm/amd/display NULL checks for adev->dm.dc in
      amdgpu_dm_fini() (bsc#1223714).

  * CVE-2024-27039: Fixed clk/hisilicon/hi3559a an erroneous devm_kfree()
      (bsc#1223821).

  * CVE-2024-27038: Fixed clk_core_get NULL pointer dereference (bsc#1223816).

  * CVE-2024-27030: Fixed octeontx2-af to use separate handlers for interrupts
      (bsc#1223790).

  * CVE-2024-27014: Fixed net/mlx5e to prevent deadlock while disabling aRFS
      (bsc#1223735).

  * CVE-2024-27013: Fixed tun limit printing rate when illegal packet received
      by tun device (bsc#1223745).

  * CVE-2024-26993: Fixed fs/sysfs reference leak in
      sysfs_break_active_protection() (bsc#1223693).

  * CVE-2024-26982: Fixed Squashfs inode number check not to be an invalid value
      of zero (bsc#1223634).

  * CVE-2024-26970: Fixed clk/qcom/gcc-ipq6018 termination of frequency table
      arrays (bsc#1223644).

  * CVE-2024-26969: Fixed clk/qcom/gcc-ipq8074 termination of frequency table
      arrays (bsc#1223645).

  * CVE-2024-26966: Fixed clk/qcom/mmcc-apq8084 termination of frequency table
      arrays (bsc#1223646).

  * CVE-2024-26965: Fixed clk/qcom/mmcc-msm8974 termination of frequency table
      arrays (bsc#1223648).

  * CVE-2024-26960: Fixed mm/swap race between free_swap_and_cache() and
      swapoff() (bsc#1223655).

  * CVE-2024-26951: Fixed wireguard/netlink check for dangling peer via is_dead
      instead of empty list (bsc#1223660).

  * CVE-2024-26950: Fixed wireguard/netlink to access device through ctx instead
      of peer (bsc#1223661).

  * CVE-2024-26948: Fixed drm/amd/display by adding dc_state NULL check in
      dc_state_release (bsc#1223664).

  * CVE-2024-26927: Fixed ASoC/SOF bounds checking to firmware data Smatch
      (bsc#1223525).

  * CVE-2024-26901: Fixed do_sys_name_to_handle() to use kzalloc() to prevent
      kernel-infoleak (bsc#1223198).

  * CVE-2024-26896: Fixed wifi/wfx memory leak when start ...

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra-debuginfo", rpm:"kernel-rt-extra-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debuginfo", rpm:"kernel-rt_debug-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch-devel", rpm:"kernel-rt-livepatch-devel~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_13_52-rt-1", rpm:"kernel-livepatch-5_14_21-150500_13_52-rt-1~150500.11.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt", rpm:"reiserfs-kmp-rt~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-optional-debuginfo", rpm:"kernel-rt-optional-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debugsource", rpm:"kernel-rt_debug-debugsource~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-optional", rpm:"kernel-rt-optional~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt-debuginfo", rpm:"kselftests-kmp-rt-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt-debuginfo", rpm:"dlm-kmp-rt-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra", rpm:"kernel-rt-extra~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt-debuginfo", rpm:"gfs2-kmp-rt-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP5-RT_Update_14-debugsource-1", rpm:"kernel-livepatch-SLE15-SP5-RT_Update_14-debugsource-1~150500.11.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel-debuginfo", rpm:"kernel-rt_debug-devel-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-vdso", rpm:"kernel-rt_debug-vdso~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-livepatch-devel", rpm:"kernel-rt_debug-livepatch-devel~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch", rpm:"kernel-rt-livepatch~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_13_52-rt-debuginfo-1", rpm:"kernel-livepatch-5_14_21-150500_13_52-rt-debuginfo-1~150500.11.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt-debuginfo", rpm:"cluster-md-kmp-rt-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt", rpm:"kselftests-kmp-rt~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-vdso", rpm:"kernel-rt-vdso~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt-debuginfo", rpm:"ocfs2-kmp-rt-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-debuginfo", rpm:"kernel-rt-devel-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-vdso-debuginfo", rpm:"kernel-rt-vdso-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt-debuginfo", rpm:"reiserfs-kmp-rt-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-vdso-debuginfo", rpm:"kernel-rt_debug-vdso-debuginfo~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.14.21~150500.13.52.1", rls:"openSUSELeap15.5"))) {
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