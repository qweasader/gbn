# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856522");
  script_version("2024-10-10T07:25:31+0000");
  script_cve_id("CVE-2021-4204", "CVE-2021-4441", "CVE-2021-47106", "CVE-2021-47517", "CVE-2021-47546", "CVE-2022-0500", "CVE-2022-23222", "CVE-2022-38457", "CVE-2022-40133", "CVE-2022-4382", "CVE-2022-48645", "CVE-2022-48706", "CVE-2022-48808", "CVE-2022-48865", "CVE-2022-48868", "CVE-2022-48869", "CVE-2022-48870", "CVE-2022-48871", "CVE-2022-48872", "CVE-2022-48873", "CVE-2022-48875", "CVE-2022-48878", "CVE-2022-48880", "CVE-2022-48881", "CVE-2022-48882", "CVE-2022-48883", "CVE-2022-48884", "CVE-2022-48885", "CVE-2022-48886", "CVE-2022-48887", "CVE-2022-48888", "CVE-2022-48889", "CVE-2022-48890", "CVE-2022-48891", "CVE-2022-48893", "CVE-2022-48896", "CVE-2022-48898", "CVE-2022-48899", "CVE-2022-48903", "CVE-2022-48904", "CVE-2022-48905", "CVE-2022-48906", "CVE-2022-48907", "CVE-2022-48909", "CVE-2022-48910", "CVE-2022-48912", "CVE-2022-48913", "CVE-2022-48914", "CVE-2022-48915", "CVE-2022-48916", "CVE-2022-48917", "CVE-2022-48918", "CVE-2022-48919", "CVE-2022-48920", "CVE-2022-48921", "CVE-2022-48923", "CVE-2022-48924", "CVE-2022-48925", "CVE-2022-48926", "CVE-2022-48927", "CVE-2022-48928", "CVE-2022-48929", "CVE-2022-48930", "CVE-2022-48931", "CVE-2022-48932", "CVE-2022-48934", "CVE-2022-48937", "CVE-2022-48938", "CVE-2022-48939", "CVE-2022-48940", "CVE-2022-48941", "CVE-2022-48942", "CVE-2022-48943", "CVE-2023-3610", "CVE-2023-52458", "CVE-2023-52489", "CVE-2023-52498", "CVE-2023-52581", "CVE-2023-52859", "CVE-2023-52887", "CVE-2023-52889", "CVE-2023-52893", "CVE-2023-52894", "CVE-2023-52896", "CVE-2023-52898", "CVE-2023-52899", "CVE-2023-52900", "CVE-2023-52901", "CVE-2023-52904", "CVE-2023-52905", "CVE-2023-52906", "CVE-2023-52907", "CVE-2023-52908", "CVE-2023-52909", "CVE-2023-52910", "CVE-2023-52911", "CVE-2023-52912", "CVE-2023-52913", "CVE-2024-26631", "CVE-2024-26668", "CVE-2024-26669", "CVE-2024-26677", "CVE-2024-26735", "CVE-2024-26808", "CVE-2024-26812", "CVE-2024-26835", "CVE-2024-26851", "CVE-2024-27010", "CVE-2024-27011", "CVE-2024-27016", "CVE-2024-27024", "CVE-2024-27079", "CVE-2024-27403", "CVE-2024-31076", "CVE-2024-35897", "CVE-2024-35902", "CVE-2024-35945", "CVE-2024-35971", "CVE-2024-36009", "CVE-2024-36013", "CVE-2024-36270", "CVE-2024-36286", "CVE-2024-36489", "CVE-2024-36929", "CVE-2024-36933", "CVE-2024-36936", "CVE-2024-36962", "CVE-2024-38554", "CVE-2024-38602", "CVE-2024-38662", "CVE-2024-39489", "CVE-2024-40905", "CVE-2024-40978", "CVE-2024-40980", "CVE-2024-40995", "CVE-2024-41000", "CVE-2024-41007", "CVE-2024-41009", "CVE-2024-41011", "CVE-2024-41016", "CVE-2024-41020", "CVE-2024-41022", "CVE-2024-41035", "CVE-2024-41036", "CVE-2024-41038", "CVE-2024-41039", "CVE-2024-41042", "CVE-2024-41045", "CVE-2024-41056", "CVE-2024-41060", "CVE-2024-41062", "CVE-2024-41065", "CVE-2024-41068", "CVE-2024-41073", "CVE-2024-41079", "CVE-2024-41080", "CVE-2024-41087", "CVE-2024-41088", "CVE-2024-41089", "CVE-2024-41092", "CVE-2024-41093", "CVE-2024-41095", "CVE-2024-41097", "CVE-2024-41098", "CVE-2024-42069", "CVE-2024-42074", "CVE-2024-42076", "CVE-2024-42077", "CVE-2024-42080", "CVE-2024-42082", "CVE-2024-42085", "CVE-2024-42086", "CVE-2024-42087", "CVE-2024-42089", "CVE-2024-42090", "CVE-2024-42092", "CVE-2024-42095", "CVE-2024-42097", "CVE-2024-42098", "CVE-2024-42101", "CVE-2024-42104", "CVE-2024-42106", "CVE-2024-42107", "CVE-2024-42110", "CVE-2024-42114", "CVE-2024-42115", "CVE-2024-42119", "CVE-2024-42120", "CVE-2024-42121", "CVE-2024-42126", "CVE-2024-42127", "CVE-2024-42130", "CVE-2024-42137", "CVE-2024-42139", "CVE-2024-42142", "CVE-2024-42143", "CVE-2024-42148", "CVE-2024-42152", "CVE-2024-42155", "CVE-2024-42156", "CVE-2024-42157", "CVE-2024-42158", "CVE-2024-42162", "CVE-2024-42223", "CVE-2024-42225", "CVE-2024-42228", "CVE-2024-42229", "CVE-2024-42230", "CVE-2024-42232", "CVE-2024-42236", "CVE-2024-42237", "CVE-2024-42238", "CVE-2024-42239", "CVE-2024-42240", "CVE-2024-42244", "CVE-2024-42246", "CVE-2024-42247", "CVE-2024-42268", "CVE-2024-42271", "CVE-2024-42274", "CVE-2024-42276", "CVE-2024-42277", "CVE-2024-42280", "CVE-2024-42281", "CVE-2024-42283", "CVE-2024-42284", "CVE-2024-42285", "CVE-2024-42286", "CVE-2024-42287", "CVE-2024-42288", "CVE-2024-42289", "CVE-2024-42291", "CVE-2024-42292", "CVE-2024-42295", "CVE-2024-42301", "CVE-2024-42302", "CVE-2024-42308", "CVE-2024-42309", "CVE-2024-42310", "CVE-2024-42311", "CVE-2024-42312", "CVE-2024-42313", "CVE-2024-42315", "CVE-2024-42318", "CVE-2024-42319", "CVE-2024-42320", "CVE-2024-42322", "CVE-2024-43816", "CVE-2024-43818", "CVE-2024-43819", "CVE-2024-43821", "CVE-2024-43823", "CVE-2024-43829", "CVE-2024-43830", "CVE-2024-43831", "CVE-2024-43834", "CVE-2024-43837", "CVE-2024-43839", "CVE-2024-43841", "CVE-2024-43842", "CVE-2024-43846", "CVE-2024-43849", "CVE-2024-43853", "CVE-2024-43854", "CVE-2024-43856", "CVE-2024-43858", "CVE-2024-43860", "CVE-2024-43861", "CVE-2024-43863", "CVE-2024-43866", "CVE-2024-43867", "CVE-2024-43871", "CVE-2024-43872", "CVE-2024-43873", "CVE-2024-43879", "CVE-2024-43880", "CVE-2024-43882", "CVE-2024-43883", "CVE-2024-43884", "CVE-2024-43889", "CVE-2024-43892", "CVE-2024-43893", "CVE-2024-43894", "CVE-2024-43895", "CVE-2024-43899", "CVE-2024-43900", "CVE-2024-43902", "CVE-2024-43903", "CVE-2024-43904", "CVE-2024-43905", "CVE-2024-43907", "CVE-2024-43908", "CVE-2024-43909", "CVE-2024-44938", "CVE-2024-44939", "CVE-2024-44947");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-27 14:38:32 +0000 (Tue, 27 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-09-30 04:00:31 +0000 (Mon, 30 Sep 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:3483-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3483-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2HO244EHQ65DPDJ2NOBAXLG7QYWSCUMA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:3483-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2024-44947: Initialize beyond-EOF page contents before setting up-to-date
      (bsc#1229454).

  * CVE-2024-36936: Touch soft lockup during memory accept (bsc#1225773).

  * CVE-2022-48706: Do proper cleanup if IFCVF init fails (bsc#1225524).

  * CVE-2024-43883: Do not drop references before new references are gained
      (bsc#1229707).

  * CVE-2024-41062: Sync sock recv cb and release (bsc#1228576).

  * CVE-2024-43861: Fix memory leak for not ip packets (bsc#1229500).

  * CVE-2024-36270: Fix reference in patches.suse/netfilter-tproxy-bail-out-if-
      IP-has-been-disabled-on.patch (bsc#1226798)

  * CVE-2023-52489: Fix race in accessing memory_section->usage (bsc#1221326).

  * CVE-2024-43893: Check uartclk for zero to avoid divide by zero
      (bsc#1229759).

  * CVE-2024-43821: Fix a possible null pointer dereference (bsc#1229315).

  * CVE-2024-43900: Avoid use-after-free in load_firmware_cb() (bsc#1229756).

  * CVE-2024-44938: Fix shift-out-of-bounds in dbDiscardAG (bsc#1229792).

  * CVE-2024-44939: Fix null ptr deref in dtInsertEntry (bsc#1229820).

  * CVE-2024-41087: Fix double free on error (CVE-2024-41087,bsc#1228466).

  * CVE-2024-42277: Avoid NULL deref in sprd_iommu_hw_en (bsc#1229409).

  * CVE-2024-43902: Add null checker before passing variables (bsc#1229767).

  * CVE-2024-43904: Add null checks for 'stream' and 'plane' before
      dereferencing (bsc#1229768)

  * CVE-2024-43880: Put back removed method in struct objagg_ops (bsc#1229481).

  * CVE-2024-43884: Add error handling to pair_device() (bsc#1229739)

  * CVE-2024-43899: Fix null pointer deref in dcn20_resource.c (bsc#1229754).

  * CVE-2022-48920: Get rid of warning on transaction commit when using
      flushoncommit (bsc#1229658).

  * CVE-2023-52906: Fix warning during failed attribute validation
      (bsc#1229527).

  * CVE-2024-43882: Fixed ToCToU between perm check and set-uid/gid usage.
      (bsc#1229503)

  * CVE-2024-43866: Always drain health in shutdown callback (bsc#1229495).

  * CVE-2024-26812: Struct virqfd kABI workaround (bsc#1222808).

  * CVE-2022-48912: Fix use-after-free in __nf_register_net_hook() (bsc#1229641)

  * CVE-2024-27010: Fix mirred deadlock on device recursion (bsc#1223720).

  * CVE-2022-48906: Correctly set DATA_FIN timeout when number of retransmits is
      large (bsc#1229605)

  * CVE-2024-42155: Wipe copies of protected- and secure-keys (bsc#1228733).

  * CVE-2024-42156: Wipe  ...

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-livepatch-devel", rpm:"kernel-debug-livepatch-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso-debuginfo", rpm:"kernel-kvmsmall-vdso-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso", rpm:"kernel-kvmsmall-vdso~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-vdso", rpm:"kernel-debug-vdso~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso", rpm:"kernel-default-vdso~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-vdso-debuginfo", rpm:"kernel-debug-vdso-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso-debuginfo", rpm:"kernel-default-vdso-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-livepatch-devel", rpm:"kernel-kvmsmall-livepatch-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debugsource", rpm:"kernel-kvmsmall-debugsource~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debuginfo", rpm:"kernel-kvmsmall-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-rebuild", rpm:"kernel-default-base-rebuild~5.14.21~150500.55.80.2.150500.6.35.6", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel-debuginfo", rpm:"kernel-kvmsmall-devel-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150500.55.80.2.150500.6.35.6", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default-debuginfo", rpm:"dlm-kmp-default-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default-debuginfo", rpm:"ocfs2-kmp-default-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional-debuginfo", rpm:"kernel-default-optional-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default", rpm:"kselftests-kmp-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch-devel", rpm:"kernel-default-livepatch-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default-debuginfo", rpm:"cluster-md-kmp-default-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default-debuginfo", rpm:"kselftests-kmp-default-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra-debuginfo", rpm:"kernel-default-extra-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default-debuginfo", rpm:"gfs2-kmp-default-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional", rpm:"kernel-default-optional~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_55_80-default-debuginfo-1", rpm:"kernel-livepatch-5_14_21-150500_55_80-default-debuginfo-1~150500.11.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP5_Update_19-debugsource-1", rpm:"kernel-livepatch-SLE15-SP5_Update_19-debugsource-1~150500.11.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_55_80-default-1", rpm:"kernel-livepatch-5_14_21-150500_55_80-default-1~150500.11.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-aarch64", rpm:"dtb-aarch64~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-arm", rpm:"dtb-arm~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb", rpm:"gfs2-kmp-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debuginfo", rpm:"kernel-64kb-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amazon", rpm:"dtb-amazon~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debugsource", rpm:"kernel-64kb-debugsource~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-altera", rpm:"dtb-altera~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional-debuginfo", rpm:"kernel-64kb-optional-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-lg", rpm:"dtb-lg~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-exynos", rpm:"dtb-exynos~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-rockchip", rpm:"dtb-rockchip~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-qcom", rpm:"dtb-qcom~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb", rpm:"ocfs2-kmp-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amlogic", rpm:"dtb-amlogic~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel-debuginfo", rpm:"kernel-64kb-devel-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb", rpm:"kselftests-kmp-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-nvidia", rpm:"dtb-nvidia~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb-debuginfo", rpm:"kselftests-kmp-64kb-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb", rpm:"cluster-md-kmp-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amd", rpm:"dtb-amd~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-xilinx", rpm:"dtb-xilinx~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb-debuginfo", rpm:"reiserfs-kmp-64kb-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb-debuginfo", rpm:"dlm-kmp-64kb-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-allwinner", rpm:"dtb-allwinner~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-broadcom", rpm:"dtb-broadcom~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-socionext", rpm:"dtb-socionext~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-sprd", rpm:"dtb-sprd~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-freescale", rpm:"dtb-freescale~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apm", rpm:"dtb-apm~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apple", rpm:"dtb-apple~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb", rpm:"dlm-kmp-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional", rpm:"kernel-64kb-optional~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb", rpm:"reiserfs-kmp-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb-debuginfo", rpm:"cluster-md-kmp-64kb-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb-debuginfo", rpm:"ocfs2-kmp-64kb-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-cavium", rpm:"dtb-cavium~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-marvell", rpm:"dtb-marvell~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb-debuginfo", rpm:"gfs2-kmp-64kb-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-livepatch-devel", rpm:"kernel-64kb-livepatch-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-hisilicon", rpm:"dtb-hisilicon~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-mediatek", rpm:"dtb-mediatek~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-renesas", rpm:"dtb-renesas~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra-debuginfo", rpm:"kernel-64kb-extra-debuginfo~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
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
