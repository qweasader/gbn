# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3998.1");
  script_cve_id("CVE-2022-1882", "CVE-2022-2153", "CVE-2022-28748", "CVE-2022-2964", "CVE-2022-2978", "CVE-2022-3169", "CVE-2022-33981", "CVE-2022-3424", "CVE-2022-3435", "CVE-2022-3521", "CVE-2022-3524", "CVE-2022-3526", "CVE-2022-3535", "CVE-2022-3542", "CVE-2022-3545", "CVE-2022-3565", "CVE-2022-3577", "CVE-2022-3586", "CVE-2022-3594", "CVE-2022-3619", "CVE-2022-3621", "CVE-2022-3625", "CVE-2022-3628", "CVE-2022-3629", "CVE-2022-3633", "CVE-2022-3640", "CVE-2022-3646", "CVE-2022-3649", "CVE-2022-40476", "CVE-2022-40768", "CVE-2022-41674", "CVE-2022-42703", "CVE-2022-42719", "CVE-2022-42720", "CVE-2022-42721", "CVE-2022-42722", "CVE-2022-43750");
  script_tag(name:"creation_date", value:"2022-11-16 04:24:29 +0000 (Wed, 16 Nov 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 14:06:09 +0000 (Tue, 18 Oct 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3998-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3998-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223998-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:3998-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15-SP4 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2022-1882: Fixed a use-after-free flaw in free_pipe_info() that
 could allow a local user to crash or potentially escalate their
 privileges on the system (bsc#1199904).

CVE-2022-2153: Fixed vulnerability in KVM that could allow an
 unprivileged local attacker on the host to cause DoS (bnc#1200788).

CVE-2022-2964, CVE-2022-28748: Fixed memory corruption issues in
 ax88179_178a devices (bnc#1202686 bsc#1196018).

CVE-2022-2978: Fixed use-after-free in the NILFS file system that could
 lead to local privilege escalation or DoS (bnc#1202700).

CVE-2022-3169: Fixed a denial of service flaw which occurs when
 consecutive requests to NVME_IOCTL_RESET and the NVME_IOCTL_SUBSYS_RESET
 are sent (bnc#1203290).

CVE-2022-33981: Fixed a use-after-free in floppy driver (bnc#1200692).

CVE-2022-3424: Fixed use-after-free in gru_set_context_option(),
 gru_fault() and gru_handle_user_call_os() that could lead to kernel
 panic (bsc#1204166).

CVE-2022-3435: Fixed an out-of-bounds read in fib_nh_match() of the file
 net/ipv4/fib_semantics.c (bsc#1204171).

CVE-2022-3521: Fixed race condition in kcm_tx_work() in
 net/kcm/kcmsock.c (bnc#1204355).

CVE-2022-3524: Fixed memory leak in ipv6_renew_options() in the IPv6
 handler (bnc#1204354).

CVE-2022-3526: Fixed a memory leak in macvlan_handle_frame() from
 drivers/net/macvlan.c (bnc#1204353).

CVE-2022-3535: Fixed memory leak in mvpp2_dbgfs_port_init() in
 drivers/net/ethernet/marvell/mvpp2/mvpp2_debugfs.c (bnc#1204417).

CVE-2022-3542: Fixed memory leak in bnx2x_tpa_stop() in
 drivers/net/ethernet/broadcom/bnx2x/bnx2x_cmn.c (bnc#1204402).

CVE-2022-3545: Fixed use-after-free in area_cache_get() in
 drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c (bnc#1204415).

CVE-2022-3565: Fixed use-after-free in del_timer() in
 drivers/isdn/mISDN/l1oip_core.c (bnc#1204431).

CVE-2022-3577: Fixed out-of-bounds memory write flaw in bigben device
 driver that could lead to local privilege escalation or DoS
 (bnc#1204470).

CVE-2022-3586: Fixed use-after-free in socket buffer (SKB) that could
 allow a local unprivileged user to cause a denial of service
 (bnc#1204439).

CVE-2022-3594: Fixed excessive data logging in intr_callback() in
 drivers/net/usb/r8152.c (bnc#1204479).

CVE-2022-3619: Fixed memory leak in l2cap_recv_acldata() in
 net/bluetooth/l2cap_core.c of the component (bnc#1204569).

CVE-2022-3621: Fixed null pointer dereference in
 nilfs_bmap_lookup_at_level() in fs/nilfs2/inode.c (bnc#1204574).

CVE-2022-3625: Fixed use-after-free in
 devlink_param_set()/devlink_param_get() in net/core/devlink.c
 (bnc#1204637).

CVE-2022-3628: Fixed potential buffer overflow in
 brcmf_fweh_event_worker() in wifi/brcmfmac (bsc#1204868).

CVE-2022-3629: Fixed memory leak in vsock_connect() in
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.14.21~150400.14.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.14.21~150400.14.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.14.21~150400.14.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.14.21~150400.14.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.14.21~150400.14.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.14.21~150400.14.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.14.21~150400.14.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.14.21~150400.14.21.1", rls:"SLES15.0SP4"))) {
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
