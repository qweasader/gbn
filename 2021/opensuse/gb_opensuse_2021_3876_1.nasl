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
  script_oid("1.3.6.1.4.1.25623.1.0.854338");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2018-13405", "CVE-2018-9517", "CVE-2019-3874", "CVE-2019-3900", "CVE-2020-0429", "CVE-2020-12770", "CVE-2020-3702", "CVE-2020-4788", "CVE-2021-0941", "CVE-2021-20322", "CVE-2021-22543", "CVE-2021-31916", "CVE-2021-33033", "CVE-2021-33909", "CVE-2021-34556", "CVE-2021-34981", "CVE-2021-3542", "CVE-2021-35477", "CVE-2021-3640", "CVE-2021-3653", "CVE-2021-3655", "CVE-2021-3656", "CVE-2021-3659", "CVE-2021-3679", "CVE-2021-3715", "CVE-2021-37159", "CVE-2021-3732", "CVE-2021-3744", "CVE-2021-3752", "CVE-2021-3753", "CVE-2021-37576", "CVE-2021-3759", "CVE-2021-3760", "CVE-2021-3764", "CVE-2021-3772", "CVE-2021-38160", "CVE-2021-38198", "CVE-2021-38204", "CVE-2021-40490", "CVE-2021-41864", "CVE-2021-42008", "CVE-2021-42252", "CVE-2021-42739");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 18:55:00 +0000 (Thu, 10 Mar 2022)");
  script_tag(name:"creation_date", value:"2021-12-03 02:03:03 +0000 (Fri, 03 Dec 2021)");
  script_name("openSUSE: Security Advisory for the (openSUSE-SU-2021:3876-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3876-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JOIHHN3KQX7O34NG25NJOF7PFEZF2TVP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the'
  package(s) announced via the openSUSE-SU-2021:3876-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 LTSS kernel was updated to receive
     various security and bugfixes.

     The following security bugs were fixed:

  - Unprivileged BPF has been disabled by default to reduce attack surface
       as too many security issues have happened in the past (jsc#SLE-22573)

       You can re-enable via systemctl setting
     /proc/sys/kernel/unprivileged_bpf_disabled to 0.
     (kernel.unprivileged_bpf_disabled = 0)

  - CVE-2021-0941: In bpf_skb_change_head of filter.c, there is a possible
       out of bounds read due to a use after free. This could lead to local
       escalation of privilege with System execution privileges needed. User
       interaction is not needed for exploitation (bnc#1192045).

  - CVE-2021-31916: An out-of-bounds (OOB) memory write flaw was found in
       list_devices in drivers/md/dm-ioctl.c in the Multi-device driver module
       in the Linux kernel A bound check failure allowed an attacker with
       special user (CAP_SYS_ADMIN) privilege to gain access to out-of-bounds
       memory leading to a system crash or a leak of internal kernel
       information. The highest threat from this vulnerability is to system
       availability (bnc#1192781).

  - CVE-2021-20322: Make the ipv4 and ipv6 ICMP exception caches less
       predictive to avoid information leaks about UDP ports in use.
       (bsc#1191790)

  - CVE-2021-34981: Fixed file refcounting in cmtp when cmtp_attach_device
       fails  (bsc#1191961).

  - CVE-2021-37159: hso_free_net_device in drivers/net/usb/hso.c in the
       Linux kernel calls unregister_netdev without checking for the
       NETREG_REGISTERED state, leading to a use-after-free and a double free
       (bnc#1188601).

  - CVE-2021-3772: Fixed sctp vtag check in sctp_sf_ootb (bsc#1190351).

  - CVE-2021-3655: Missing size validations on inbound SCTP packets may have
       allowed the kernel to read uninitialized memory (bnc#1188563).

  - CVE-2021-33033: The Linux kernel has a use-after-free in cipso_v4_genopt
       in net/ipv4/cipso_ipv4.c because the CIPSO and CALIPSO refcounting for
       the DOI definitions is mishandled, aka CID-ad5d07f4a9cd. This leads to
       writing an arbitrary value (bnc#1186109 bnc#1186390 bnc#1188876).

  - CVE-2021-3760: Fixed a use-after-free vulnerability with the
       ndev- rf_conn_info object (bsc#1190067).

  - CVE-2021-42739: The firewire subsystem in the Linux kernel has a buffer
       overflow related to drivers/media/firewire/firedtv-avc.c and
       drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt mishandled
       bounds ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-devel-debuginfo", rpm:"kernel-vanilla-devel-debuginfo~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-livepatch-devel", rpm:"kernel-vanilla-livepatch-devel~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base-debuginfo", rpm:"kernel-debug-base-debuginfo~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-base", rpm:"kernel-kvmsmall-base~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-base-debuginfo", rpm:"kernel-kvmsmall-base-debuginfo~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-man", rpm:"kernel-zfcpdump-man~4.12.14~197.102.2", rls:"openSUSELeap15.3"))) {
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
