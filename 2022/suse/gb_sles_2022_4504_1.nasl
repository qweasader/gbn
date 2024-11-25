# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4504.1");
  script_cve_id("CVE-2022-2602", "CVE-2022-3176", "CVE-2022-3566", "CVE-2022-3567", "CVE-2022-3635", "CVE-2022-3643", "CVE-2022-3707", "CVE-2022-3903", "CVE-2022-4095", "CVE-2022-4129", "CVE-2022-4139", "CVE-2022-41850", "CVE-2022-41858", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-42895", "CVE-2022-42896", "CVE-2022-4378", "CVE-2022-43945", "CVE-2022-45869", "CVE-2022-45888", "CVE-2022-45934");
  script_tag(name:"creation_date", value:"2022-12-19 04:19:33 +0000 (Mon, 19 Dec 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 01:27:19 +0000 (Mon, 28 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4504-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4504-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224504-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:4504-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-4378: Fixed stack overflow in __do_proc_dointvec (bsc#1206207).

CVE-2022-42328: Guests could trigger denial of service via the netback
 driver (bnc#1206114).

CVE-2022-42329: Guests could trigger denial of service via the netback
 driver (bnc#1206113).

CVE-2022-3643: Guests could trigger NIC interface reset/abort/crash via
 netback driver (bnc#1206113).

CVE-2022-3635: Fixed a use-after-free in the tst_timer() of the file
 drivers/atm/idt77252.c of the component IPsec (bsc#1204631). -
 CVE-2022-41850: Fixed a race condition in roccat_report_event() in
 drivers/hid/hid-roccat.c (bsc#1203960).

CVE-2022-45934: Fixed a integer wraparound via L2CAP_CONF_REQ packets in
 l2cap_config_req in net/bluetooth/l2cap_core.c (bsc#1205796).

CVE-2022-3567: Fixed a to race condition in
 inet6_stream_ops()/inet6_dgram_ops() of the component IPv6 Handler
 (bsc#1204414).

CVE-2022-41858: Fixed a denial of service in sl_tx_timeout() in
 drivers/net/slip (bsc#1205671).

CVE-2022-43945: Fixed a buffer overflow in the NFSD implementation
 (bsc#1205128).

CVE-2022-4095: Fixed a use-after-free in rtl8712 driver (bsc#1205514).

CVE-2022-3903: Fixed a denial of service with the Infrared Transceiver
 USB driver (bsc#1205220).

CVE-2022-45869: Fixed a race condition in the x86 KVM subsystem which
 could cause a denial of service (bsc#1205882).

CVE-2022-45888: Fixed a use-after-free during physical removal of a USB
 devices when using drivers/char/xillybus/xillyusb.c (bsc#1205764).

CVE-2022-4139: Fixed an issue with the i915 driver that allowed the GPU
 to access any physical memory (bsc#1205700).

CVE-2022-4129: Fixed a denial of service with the Layer 2 Tunneling
 Protocol (L2TP). A missing lock when clearing sk_user_data can lead to a
 race condition and NULL pointer dereference. (bsc#1205711)

CVE-2022-42896: Fixed a use-after-free vulnerability in the
 net/bluetooth/l2cap_core.c's l2cap_connect() and l2cap_le_connect_req()
 which may have allowed code execution and leaking kernel memory
 (respectively) remotely via Bluetooth (bsc#1205709).

CVE-2022-42895: Fixed an information leak in the
 net/bluetooth/l2cap_core.c's l2cap_parse_conf_req() which can be used to
 leak kernel pointers remotely (bsc#1205705).

CVE-2022-3566: Fixed a race condition in the functions
 tcp_getsockopt/tcp_setsockopt of the component TCP Handler. The
 manipulation leads to race condition (bsc#1204405).

CVE-2022-2602: Fixed a local privilege escalation vulnerability
 involving Unix socket Garbage Collection and io_uring (bsc#1204228).

CVE-2022-3176: Fixed a use-after-free in io_uring related to
 signalfd_poll() and binder_poll() (bsc#1203391).

CVE-2022-3707: Fixed a double free in the Intel GVT-g graphics driver
 (bsc#1204780).

CVE-2022-41850: Fixed a ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.14.21~150400.14.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.14.21~150400.14.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.14.21~150400.14.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.14.21~150400.14.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.14.21~150400.14.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.14.21~150400.14.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.14.21~150400.14.28.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.14.21~150400.14.28.1", rls:"SLES15.0SP4"))) {
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
