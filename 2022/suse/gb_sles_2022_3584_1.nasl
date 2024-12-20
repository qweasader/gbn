# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3584.1");
  script_cve_id("CVE-2022-20008", "CVE-2022-2503", "CVE-2022-2663", "CVE-2022-3239", "CVE-2022-3303", "CVE-2022-39188", "CVE-2022-41218", "CVE-2022-41848");
  script_tag(name:"creation_date", value:"2022-10-17 05:00:13 +0000 (Mon, 17 Oct 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-21 18:07:55 +0000 (Wed, 21 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3584-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3584-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223584-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:3584-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated.

The following security bugs were fixed:

CVE-2022-3303: Fixed a race condition in the sound subsystem due to
 improper locking (bnc#1203769).

CVE-2022-41218: Fixed an use-after-free caused by refcount races in
 drivers/media/dvb-core/dmxdev.c (bnc#1202960).

CVE-2022-3239: Fixed an use-after-free in the video4linux driver that
 could lead a local user to able to crash the system or escalate their
 privileges (bnc#1203552).

CVE-2022-41848: Fixed a race condition and resultant use-after-free if a
 physically proximate attacker removes a PCMCIA device while calling
 ioctl (bnc#1203987).

CVE-2022-2503: Fixed a vulnerability that allowed root to bypass LoadPin
 and load untrusted and unverified kernel modules and firmware
 (bnc#1202677).

CVE-2022-20008: Fixed a bug which allowed to read kernel heap memory due
 to uninitialized data. This could lead to local information disclosure
 if reading from an SD card that triggers errors, with no additional
 execution privileges needed. (bnc#1199564)

CVE-2022-2663: Fixed an issue which allowed a firewall to be bypassed
 when users are using unencrypted IRC with nf_conntrack_irc configured
 (bnc#1202097).

CVE-2022-39188: Fixed a race condition where a device driver can free a
 page while it still has stale TLB entries. (bnc#1203107).

The following non-security bugs were fixed:

arm64: cpufeature: Allow different PMU versions in ID_DFR0_EL1
 (git-fixes)

cifs: alloc_mid function should be marked as static (bsc#1190317).

cifs: alloc_path_with_tree_prefix: do not append sep. if the path is
 empty (bsc#1190317).

cifs: change smb2_query_info_compound to use a cached fid, if available
 (bsc#1190317).

cifs: check for smb1 in open_cached_dir() (bsc#1190317).

cifs: Check the IOCB_DIRECT flag, not O_DIRECT (bsc#1190317).

cifs: clean up an inconsistent indenting (bsc#1190317).

cifs: convert the path to utf16 in smb2_query_info_compound
 (bsc#1190317).

cifs: Do not use tcon->cfid directly, use the cfid we get from
 open_cached_dir (bsc#1190317).

cifs: do not use uninitialized data in the owner/group sid (bsc#1190317).

cifs: fix double free race when mount fails in cifs_get_root()
 (bsc#1190317).

cifs: fix FILE_BOTH_DIRECTORY_INFO definition (bsc#1190317).

cifs: fix handlecache and multiuser (bsc#1190317).

cifs: fix lock length calculation (bsc#1190317).

cifs: fix ntlmssp auth when there is no key exchange (bsc#1190317).

cifs: fix NULL ptr dereference in refresh_mounts() (bsc#1190317).

cifs: fix NULL ptr dereference in smb2_ioctl_query_info() (bsc#1190317).

cifs: fix set of group SID via NTSD xattrs (bsc#1190317).

cifs: fix signed integer overflow when fl_end is OFFSET_MAX
 (bsc#1190317).

cifs: Fix smb311_update_preauth_hash() kernel-doc comment (bsc#1190317).

cifs: fix the cifs_reconnect path for DFS (bsc#1190317).

cifs: fix uninitialized pointer in error case in ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.112.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.112.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.112.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.112.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.112.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.112.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.112.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.112.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.112.1", rls:"SLES12.0SP5"))) {
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
