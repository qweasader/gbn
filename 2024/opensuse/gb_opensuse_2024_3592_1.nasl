# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856558");
  script_version("2024-10-16T08:00:45+0000");
  script_cve_id("CVE-2022-48901", "CVE-2022-48911", "CVE-2022-48923", "CVE-2022-48935", "CVE-2022-48944", "CVE-2022-48945", "CVE-2023-52610", "CVE-2023-52916", "CVE-2024-26640", "CVE-2024-26759", "CVE-2024-26767", "CVE-2024-26804", "CVE-2024-26837", "CVE-2024-37353", "CVE-2024-38538", "CVE-2024-38596", "CVE-2024-38632", "CVE-2024-40910", "CVE-2024-40973", "CVE-2024-40983", "CVE-2024-41062", "CVE-2024-41082", "CVE-2024-42154", "CVE-2024-42259", "CVE-2024-42265", "CVE-2024-42304", "CVE-2024-42305", "CVE-2024-42306", "CVE-2024-43828", "CVE-2024-43835", "CVE-2024-43890", "CVE-2024-43898", "CVE-2024-43912", "CVE-2024-43914", "CVE-2024-44935", "CVE-2024-44944", "CVE-2024-44946", "CVE-2024-44948", "CVE-2024-44950", "CVE-2024-44952", "CVE-2024-44954", "CVE-2024-44967", "CVE-2024-44969", "CVE-2024-44970", "CVE-2024-44971", "CVE-2024-44972", "CVE-2024-44977", "CVE-2024-44982", "CVE-2024-44986", "CVE-2024-44987", "CVE-2024-44988", "CVE-2024-44989", "CVE-2024-44990", "CVE-2024-44998", "CVE-2024-44999", "CVE-2024-45000", "CVE-2024-45001", "CVE-2024-45003", "CVE-2024-45006", "CVE-2024-45007", "CVE-2024-45008", "CVE-2024-45011", "CVE-2024-45013", "CVE-2024-45015", "CVE-2024-45018", "CVE-2024-45020", "CVE-2024-45021", "CVE-2024-45026", "CVE-2024-45028", "CVE-2024-45029", "CVE-2024-46673", "CVE-2024-46674", "CVE-2024-46675", "CVE-2024-46676", "CVE-2024-46677", "CVE-2024-46679", "CVE-2024-46685", "CVE-2024-46686", "CVE-2024-46689", "CVE-2024-46694", "CVE-2024-46702", "CVE-2024-46707", "CVE-2024-46714", "CVE-2024-46715", "CVE-2024-46717", "CVE-2024-46720", "CVE-2024-46721", "CVE-2024-46722", "CVE-2024-46723", "CVE-2024-46724", "CVE-2024-46725", "CVE-2024-46726", "CVE-2024-46727", "CVE-2024-46728", "CVE-2024-46730", "CVE-2024-46731", "CVE-2024-46732", "CVE-2024-46737", "CVE-2024-46738", "CVE-2024-46739", "CVE-2024-46743", "CVE-2024-46744", "CVE-2024-46745", "CVE-2024-46746", "CVE-2024-46747", "CVE-2024-46750", "CVE-2024-46751", "CVE-2024-46752", "CVE-2024-46753", "CVE-2024-46755", "CVE-2024-46756", "CVE-2024-46758", "CVE-2024-46759", "CVE-2024-46761", "CVE-2024-46771", "CVE-2024-46772", "CVE-2024-46773", "CVE-2024-46774", "CVE-2024-46778", "CVE-2024-46780", "CVE-2024-46781", "CVE-2024-46783", "CVE-2024-46784", "CVE-2024-46786", "CVE-2024-46787", "CVE-2024-46791", "CVE-2024-46794", "CVE-2024-46798", "CVE-2024-46822", "CVE-2024-46830");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-16 08:00:45 +0000 (Wed, 16 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-20 18:17:50 +0000 (Fri, 20 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-10-11 04:02:32 +0000 (Fri, 11 Oct 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:3592-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3592-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HLNBB56HQ63EA2FMCWFWXXGRB24SC4YO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:3592-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 RT kernel was updated to receive various
  security bugfixes.

  The following security bugs were fixed:

  * CVE-2022-48901: btrfs: do not start relocation until in progress drops are
      done (bsc#1229607).

  * CVE-2022-48911: kabi: add __nf_queue_get_refs() for kabi compliance.
      (bsc#1229633).

  * CVE-2022-48923: btrfs: prevent copying too big compressed lzo segment
      (bsc#1229662)

  * CVE-2022-48935: Fixed an unregister flowtable hooks on netns exit
      (bsc#1229619)

  * CVE-2023-52610: net/sched: act_ct: fix skb leak and crash on ooo frags
      (bsc#1221610).

  * CVE-2023-52916: media: aspeed: Fix memory overwrite if timing is 1600x900
      (bsc#1230269).

  * CVE-2024-26640: tcp: add sanity checks to rx zerocopy (bsc#1221650).

  * CVE-2024-26759: mm/swap: fix race when skipping swapcache (bsc#1230340).

  * CVE-2024-26767: drm/amd/display: fixed integer types and null check
      locations (bsc#1230339).

  * CVE-2024-26804: net: ip_tunnel: prevent perpetual headroom growth
      (bsc#1222629).

  * CVE-2024-26837: net: bridge: switchdev: race between creation of new group
      memberships and generation of the list of MDB events to replay
      (bsc#1222973).

  * CVE-2024-37353: virtio: fixed a double free in vp_del_vqs() (bsc#1226875).

  * CVE-2024-38538: net: bridge: xmit: make sure we have at least eth header len
      bytes (bsc#1226606).

  * CVE-2024-38596: af_unix: Fix data races in
      unix_release_sock/unix_stream_sendmsg (bsc#1226846).

  * CVE-2024-40910: Fix refcount imbalance on inbound connections (bsc#1227832).

  * CVE-2024-40973: media: mtk-vcodec: potential null pointer deference in SCP
      (bsc#1227890).

  * CVE-2024-40983: tipc: force a dst refcount before doing decryption
      (bsc#1227819).

  * CVE-2024-41062: Sync sock recv cb and release (bsc#1228576).

  * CVE-2024-41082: nvme-fabrics: use reserved tag for reg read/write command
      (bsc#1228620 CVE-2024-41082).

  * CVE-2024-42154: tcp_metrics: validate source addr length (bsc#1228507).

  * CVE-2024-42259: Fix Virtual Memory mapping boundaries calculation
      (bsc#1229156)

  * CVE-2024-42265: protect the fetch of ->fd[fd] in do_dup2() from
      mispredictions (bsc#1229334).

  * CVE-2024-42304: ext4: make sure the first directory block is not a hole
      (bsc#1229364).

  * CVE-2024-42305: ext4: check dot and dotdot of dx_root before making dir
      indexed (bsc#1229363).

  * CVE-2024-42306: udf: Avoid using corrupted block bitmap buffer
      (bsc#1229362).

  * CVE-2024-43828: ext4: fix inf ...

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP5-RT_Update_21-debugsource-1", rpm:"kernel-livepatch-SLE15-SP5-RT_Update_21-debugsource-1~150500.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel-debuginfo", rpm:"kernel-rt_debug-devel-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt-debuginfo", rpm:"ocfs2-kmp-rt-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt-debuginfo", rpm:"dlm-kmp-rt-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt-debuginfo", rpm:"kselftests-kmp-rt-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt-debuginfo", rpm:"gfs2-kmp-rt-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch", rpm:"kernel-rt-livepatch~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt", rpm:"kselftests-kmp-rt~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-debuginfo", rpm:"kernel-rt-devel-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debuginfo", rpm:"kernel-rt_debug-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_13_73-rt-1", rpm:"kernel-livepatch-5_14_21-150500_13_73-rt-1~150500.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-livepatch-devel", rpm:"kernel-rt_debug-livepatch-devel~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-optional", rpm:"kernel-rt-optional~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_13_73-rt-debuginfo-1", rpm:"kernel-livepatch-5_14_21-150500_13_73-rt-debuginfo-1~150500.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-optional-debuginfo", rpm:"kernel-rt-optional-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-vdso-debuginfo", rpm:"kernel-rt-vdso-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt", rpm:"reiserfs-kmp-rt~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-vdso", rpm:"kernel-rt-vdso~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt-debuginfo", rpm:"reiserfs-kmp-rt-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt-debuginfo", rpm:"cluster-md-kmp-rt-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch-devel", rpm:"kernel-rt-livepatch-devel~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debugsource", rpm:"kernel-rt_debug-debugsource~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-vdso", rpm:"kernel-rt_debug-vdso~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-vdso-debuginfo", rpm:"kernel-rt_debug-vdso-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra", rpm:"kernel-rt-extra~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra-debuginfo", rpm:"kernel-rt-extra-debuginfo~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150500.13.73.1", rls:"openSUSELeap15.5"))) {
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