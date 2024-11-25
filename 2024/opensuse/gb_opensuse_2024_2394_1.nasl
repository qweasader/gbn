# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856305");
  script_version("2024-08-09T05:05:42+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-4439", "CVE-2021-47089", "CVE-2021-47432", "CVE-2021-47515", "CVE-2021-47534", "CVE-2021-47538", "CVE-2021-47539", "CVE-2021-47555", "CVE-2021-47566", "CVE-2021-47571", "CVE-2021-47572", "CVE-2021-47576", "CVE-2021-47577", "CVE-2021-47578", "CVE-2021-47580", "CVE-2021-47582", "CVE-2021-47583", "CVE-2021-47584", "CVE-2021-47585", "CVE-2021-47586", "CVE-2021-47587", "CVE-2021-47589", "CVE-2021-47592", "CVE-2021-47595", "CVE-2021-47596", "CVE-2021-47597", "CVE-2021-47600", "CVE-2021-47601", "CVE-2021-47602", "CVE-2021-47603", "CVE-2021-47604", "CVE-2021-47605", "CVE-2021-47607", "CVE-2021-47608", "CVE-2021-47609", "CVE-2021-47610", "CVE-2021-47611", "CVE-2021-47612", "CVE-2021-47614", "CVE-2021-47615", "CVE-2021-47616", "CVE-2021-47617", "CVE-2021-47618", "CVE-2021-47619", "CVE-2021-47620", "CVE-2022-48711", "CVE-2022-48712", "CVE-2022-48713", "CVE-2022-48714", "CVE-2022-48715", "CVE-2022-48716", "CVE-2022-48717", "CVE-2022-48718", "CVE-2022-48720", "CVE-2022-48721", "CVE-2022-48722", "CVE-2022-48723", "CVE-2022-48724", "CVE-2022-48725", "CVE-2022-48726", "CVE-2022-48727", "CVE-2022-48728", "CVE-2022-48729", "CVE-2022-48730", "CVE-2022-48732", "CVE-2022-48733", "CVE-2022-48734", "CVE-2022-48735", "CVE-2022-48736", "CVE-2022-48737", "CVE-2022-48738", "CVE-2022-48739", "CVE-2022-48740", "CVE-2022-48743", "CVE-2022-48744", "CVE-2022-48745", "CVE-2022-48746", "CVE-2022-48747", "CVE-2022-48748", "CVE-2022-48749", "CVE-2022-48751", "CVE-2022-48752", "CVE-2022-48753", "CVE-2022-48754", "CVE-2022-48755", "CVE-2022-48756", "CVE-2022-48758", "CVE-2022-48759", "CVE-2022-48760", "CVE-2022-48761", "CVE-2022-48763", "CVE-2022-48765", "CVE-2022-48766", "CVE-2022-48767", "CVE-2022-48768", "CVE-2022-48769", "CVE-2022-48770", "CVE-2022-48771", "CVE-2022-48772", "CVE-2023-24023", "CVE-2023-52622", "CVE-2023-52658", "CVE-2023-52667", "CVE-2023-52670", "CVE-2023-52672", "CVE-2023-52675", "CVE-2023-52735", "CVE-2023-52737", "CVE-2023-52752", "CVE-2023-52766", "CVE-2023-52784", "CVE-2023-52787", "CVE-2023-52800", "CVE-2023-52835", "CVE-2023-52837", "CVE-2023-52843", "CVE-2023-52845", "CVE-2023-52846", "CVE-2023-52869", "CVE-2023-52881", "CVE-2023-52882", "CVE-2023-52884", "CVE-2024-26625", "CVE-2024-26644", "CVE-2024-26720", "CVE-2024-26842", "CVE-2024-26845", "CVE-2024-26923", "CVE-2024-26973", "CVE-2024-27432", "CVE-2024-33619", "CVE-2024-35247", "CVE-2024-35789", "CVE-2024-35790", "CVE-2024-35807", "CVE-2024-35814", "CVE-2024-35835", "CVE-2024-35848", "CVE-2024-35857", "CVE-2024-35861", "CVE-2024-35862", "CVE-2024-35864", "CVE-2024-35869", "CVE-2024-35878", "CVE-2024-35884", "CVE-2024-35886", "CVE-2024-35896", "CVE-2024-35898", "CVE-2024-35900", "CVE-2024-35905", "CVE-2024-35925", "CVE-2024-35950", "CVE-2024-35956", "CVE-2024-35958", "CVE-2024-35960", "CVE-2024-35962", "CVE-2024-35997", "CVE-2024-36005", "CVE-2024-36008", "CVE-2024-36017", "CVE-2024-36020", "CVE-2024-36021", "CVE-2024-36025", "CVE-2024-36477", "CVE-2024-36478", "CVE-2024-36479", "CVE-2024-36890", "CVE-2024-36894", "CVE-2024-36899", "CVE-2024-36900", "CVE-2024-36904", "CVE-2024-36915", "CVE-2024-36916", "CVE-2024-36917", "CVE-2024-36919", "CVE-2024-36934", "CVE-2024-36937", "CVE-2024-36940", "CVE-2024-36945", "CVE-2024-36949", "CVE-2024-36960", "CVE-2024-36964", "CVE-2024-36965", "CVE-2024-36967", "CVE-2024-36969", "CVE-2024-36971", "CVE-2024-36975", "CVE-2024-36978", "CVE-2024-37021", "CVE-2024-37078", "CVE-2024-37354", "CVE-2024-38381", "CVE-2024-38388", "CVE-2024-38390", "CVE-2024-38540", "CVE-2024-38541", "CVE-2024-38544", "CVE-2024-38545", "CVE-2024-38546", "CVE-2024-38547", "CVE-2024-38548", "CVE-2024-38549", "CVE-2024-38550", "CVE-2024-38552", "CVE-2024-38553", "CVE-2024-38555", "CVE-2024-38556", "CVE-2024-38557", "CVE-2024-38559", "CVE-2024-38560", "CVE-2024-38564", "CVE-2024-38565", "CVE-2024-38567", "CVE-2024-38568", "CVE-2024-38571", "CVE-2024-38573", "CVE-2024-38578", "CVE-2024-38579", "CVE-2024-38580", "CVE-2024-38581", "CVE-2024-38582", "CVE-2024-38583", "CVE-2024-38587", "CVE-2024-38590", "CVE-2024-38591", "CVE-2024-38594", "CVE-2024-38597", "CVE-2024-38599", "CVE-2024-38600", "CVE-2024-38601", "CVE-2024-38603", "CVE-2024-38605", "CVE-2024-38608", "CVE-2024-38616", "CVE-2024-38618", "CVE-2024-38619", "CVE-2024-38621", "CVE-2024-38627", "CVE-2024-38630", "CVE-2024-38633", "CVE-2024-38634", "CVE-2024-38635", "CVE-2024-38659", "CVE-2024-38661", "CVE-2024-38780", "CVE-2024-39301", "CVE-2024-39468", "CVE-2024-39469", "CVE-2024-39471");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-12 15:43:28 +0000 (Wed, 12 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-07-12 04:00:24 +0000 (Fri, 12 Jul 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:2394-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2394-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QL4AFERYYZIX3LRTVZHKRBBGVVFUZXJJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:2394-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 RT kernel was updated to receive various
  security bugfixes.

  The following security bugs were fixed:

  * CVE-2021-47089: kfence: fix memory leak when cat kfence objects
      (bsc#1220958.

  * CVE-2021-47432: lib/generic-radix-tree.c: Do not overflow in peek()
      (bsc#1225391).

  * CVE-2021-47515: seg6: fix the if in the IPv6 socket control block
      (bsc#1225426).

  * CVE-2021-47538: rxrpc: Fix rxrpc_local leak in rxrpc_lookup_peer()
      (bsc#1225448).

  * CVE-2021-47539: rxrpc: Fix rxrpc_peer leak in rxrpc_look_up_bundle()
      (bsc#1225452).

  * CVE-2021-47555: net: vlan: fix underflow for the real_dev refcnt
      (bsc#1225467).

  * CVE-2021-47566: Fix clearing user buffer by properly using clear_user()
      (bsc#1225514).

  * CVE-2021-47571: staging: rtl8192e: Fix use after free in
      _rtl92e_pci_disconnect() (bsc#1225518).

  * CVE-2021-47572: net: nexthop: fix null pointer dereference when IPv6 is not
      enabled (bsc#1225389).

  * CVE-2022-48716: ASoC: codecs: wcd938x: fix incorrect used of portid
      (bsc#1226678).

  * CVE-2023-24023: Bluetooth: Add more enc key size check (bsc#1218148).

  * CVE-2023-52622: ext4: avoid online resizing failures due to oversized flex
      bg (bsc#1222080).

  * CVE-2023-52658: Revert 'net/mlx5: Block entering switchdev mode with ns
      inconsistency' (bsc#1224719).

  * CVE-2023-52667: net/mlx5e: fix a potential double-free in
      fs_any_create_groups (bsc#1224603).

  * CVE-2023-52670: rpmsg: virtio: Free driver_override when rpmsg_remove()
      (bsc#1224696).

  * CVE-2023-52672: pipe: wakeup wr_wait after setting max_usage (bsc#1224614).

  * CVE-2023-52675: powerpc/imc-pmu: Add a null pointer check in
      update_events_in_group() (bsc#1224504).

  * CVE-2023-52735: bpf, sockmap: Don't let sock_map_{close,destroy,unhash} call
      itself (bsc#1225475).

  * CVE-2023-52737: btrfs: lock the inode in shared mode before starting fiemap
      (bsc#1225484).

  * CVE-2023-52752: smb: client: fix use-after-free bug in
      cifs_debug_data_proc_show() (bsc#1225487).

  * CVE-2023-52784: bonding: stop the device in bond_setup_by_slave()
      (bsc#1224946).

  * CVE-2023-52787: blk-mq: make sure active queue usage is held for
      bio_integrity_prep() (bsc#1225105).

  * CVE-2023-52835: perf/core: Bail out early if the request AUX area is out of
      bound (bsc#1225602).

  * CVE-2023-52837: nbd: fix uaf in nbd_open (bsc#1224935).

  * CVE-2023-52843: llc: verify mac len before reading mac header (bsc#1224951).

  * CVE-2023-52845: tipc: ...

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_13_61-rt-1", rpm:"kernel-livepatch-5_14_21-150500_13_61-rt-1~150500.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt-debuginfo", rpm:"kselftests-kmp-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt-debuginfo", rpm:"reiserfs-kmp-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_13_61-rt-debuginfo-1", rpm:"kernel-livepatch-5_14_21-150500_13_61-rt-debuginfo-1~150500.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel-debuginfo", rpm:"kernel-rt_debug-devel-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-debuginfo", rpm:"kernel-rt-devel-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-vdso", rpm:"kernel-rt_debug-vdso~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt-debuginfo", rpm:"dlm-kmp-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-optional-debuginfo", rpm:"kernel-rt-optional-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-optional", rpm:"kernel-rt-optional~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt", rpm:"reiserfs-kmp-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-vdso-debuginfo", rpm:"kernel-rt_debug-vdso-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP5-RT_Update_17-debugsource-1", rpm:"kernel-livepatch-SLE15-SP5-RT_Update_17-debugsource-1~150500.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt-debuginfo", rpm:"ocfs2-kmp-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt", rpm:"kselftests-kmp-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch", rpm:"kernel-rt-livepatch~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt-debuginfo", rpm:"gfs2-kmp-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra-debuginfo", rpm:"kernel-rt-extra-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-vdso", rpm:"kernel-rt-vdso~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-vdso-debuginfo", rpm:"kernel-rt-vdso-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debugsource", rpm:"kernel-rt_debug-debugsource~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-livepatch-devel", rpm:"kernel-rt_debug-livepatch-devel~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debuginfo", rpm:"kernel-rt_debug-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch-devel", rpm:"kernel-rt-livepatch-devel~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra", rpm:"kernel-rt-extra~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt-debuginfo", rpm:"cluster-md-kmp-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_13_61-rt-1", rpm:"kernel-livepatch-5_14_21-150500_13_61-rt-1~150500.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt-debuginfo", rpm:"kselftests-kmp-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt-debuginfo", rpm:"reiserfs-kmp-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_13_61-rt-debuginfo-1", rpm:"kernel-livepatch-5_14_21-150500_13_61-rt-debuginfo-1~150500.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel-debuginfo", rpm:"kernel-rt_debug-devel-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-debuginfo", rpm:"kernel-rt-devel-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-vdso", rpm:"kernel-rt_debug-vdso~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt-debuginfo", rpm:"dlm-kmp-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-optional-debuginfo", rpm:"kernel-rt-optional-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-optional", rpm:"kernel-rt-optional~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt", rpm:"reiserfs-kmp-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-vdso-debuginfo", rpm:"kernel-rt_debug-vdso-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP5-RT_Update_17-debugsource-1", rpm:"kernel-livepatch-SLE15-SP5-RT_Update_17-debugsource-1~150500.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt-debuginfo", rpm:"ocfs2-kmp-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt", rpm:"kselftests-kmp-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch", rpm:"kernel-rt-livepatch~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt-debuginfo", rpm:"gfs2-kmp-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra-debuginfo", rpm:"kernel-rt-extra-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-vdso", rpm:"kernel-rt-vdso~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-vdso-debuginfo", rpm:"kernel-rt-vdso-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debugsource", rpm:"kernel-rt_debug-debugsource~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-livepatch-devel", rpm:"kernel-rt_debug-livepatch-devel~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debuginfo", rpm:"kernel-rt_debug-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch-devel", rpm:"kernel-rt-livepatch-devel~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra", rpm:"kernel-rt-extra~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt-debuginfo", rpm:"cluster-md-kmp-rt-debuginfo~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.14.21~150500.13.61.1", rls:"openSUSELeap15.5"))) {
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
