# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1643.1");
  script_cve_id("CVE-2019-25160", "CVE-2020-36312", "CVE-2021-23134", "CVE-2021-46904", "CVE-2021-46905", "CVE-2021-46909", "CVE-2021-46938", "CVE-2021-46939", "CVE-2021-46941", "CVE-2021-46950", "CVE-2021-46955", "CVE-2021-46958", "CVE-2021-46960", "CVE-2021-46963", "CVE-2021-46964", "CVE-2021-46966", "CVE-2021-46981", "CVE-2021-46988", "CVE-2021-46990", "CVE-2021-46998", "CVE-2021-47006", "CVE-2021-47015", "CVE-2021-47024", "CVE-2021-47034", "CVE-2021-47045", "CVE-2021-47049", "CVE-2021-47055", "CVE-2021-47056", "CVE-2021-47060", "CVE-2021-47061", "CVE-2021-47063", "CVE-2021-47068", "CVE-2021-47070", "CVE-2021-47071", "CVE-2021-47073", "CVE-2021-47100", "CVE-2021-47101", "CVE-2021-47104", "CVE-2021-47110", "CVE-2021-47112", "CVE-2021-47113", "CVE-2021-47114", "CVE-2021-47117", "CVE-2021-47118", "CVE-2021-47119", "CVE-2021-47131", "CVE-2021-47138", "CVE-2021-47141", "CVE-2021-47142", "CVE-2021-47143", "CVE-2021-47146", "CVE-2021-47149", "CVE-2021-47150", "CVE-2021-47153", "CVE-2021-47159", "CVE-2021-47161", "CVE-2021-47162", "CVE-2021-47165", "CVE-2021-47166", "CVE-2021-47167", "CVE-2021-47168", "CVE-2021-47169", "CVE-2021-47171", "CVE-2021-47173", "CVE-2021-47177", "CVE-2021-47179", "CVE-2021-47180", "CVE-2021-47181", "CVE-2021-47182", "CVE-2021-47183", "CVE-2021-47184", "CVE-2021-47185", "CVE-2021-47188", "CVE-2021-47189", "CVE-2021-47198", "CVE-2021-47202", "CVE-2021-47203", "CVE-2021-47204", "CVE-2021-47205", "CVE-2021-47207", "CVE-2021-47211", "CVE-2021-47216", "CVE-2021-47217", "CVE-2022-0487", "CVE-2022-48619", "CVE-2022-48626", "CVE-2022-48636", "CVE-2022-48650", "CVE-2022-48651", "CVE-2022-48667", "CVE-2022-48668", "CVE-2022-48672", "CVE-2022-48687", "CVE-2022-48688", "CVE-2022-48695", "CVE-2022-48701", "CVE-2022-48702", "CVE-2023-0160", "CVE-2023-28746", "CVE-2023-35827", "CVE-2023-4881", "CVE-2023-52454", "CVE-2023-52469", "CVE-2023-52470", "CVE-2023-52474", "CVE-2023-52476", "CVE-2023-52477", "CVE-2023-52486", "CVE-2023-52488", "CVE-2023-52509", "CVE-2023-52515", "CVE-2023-52524", "CVE-2023-52528", "CVE-2023-52575", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52590", "CVE-2023-52591", "CVE-2023-52595", "CVE-2023-52598", "CVE-2023-52607", "CVE-2023-52614", "CVE-2023-52620", "CVE-2023-52628", "CVE-2023-52635", "CVE-2023-52639", "CVE-2023-52644", "CVE-2023-52646", "CVE-2023-52650", "CVE-2023-52652", "CVE-2023-52653", "CVE-2023-6270", "CVE-2023-6356", "CVE-2023-6535", "CVE-2023-6536", "CVE-2023-7042", "CVE-2023-7192", "CVE-2024-0639", "CVE-2024-2201", "CVE-2024-22099", "CVE-2024-23307", "CVE-2024-23848", "CVE-2024-24855", "CVE-2024-24861", "CVE-2024-26614", "CVE-2024-26642", "CVE-2024-26651", "CVE-2024-26671", "CVE-2024-26675", "CVE-2024-26689", "CVE-2024-26704", "CVE-2024-26733", "CVE-2024-26739", "CVE-2024-26743", "CVE-2024-26744", "CVE-2024-26747", "CVE-2024-26754", "CVE-2024-26763", "CVE-2024-26771", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26777", "CVE-2024-26778", "CVE-2024-26779", "CVE-2024-26791", "CVE-2024-26793", "CVE-2024-26805", "CVE-2024-26816", "CVE-2024-26817", "CVE-2024-26839", "CVE-2024-26840", "CVE-2024-26852", "CVE-2024-26855", "CVE-2024-26857", "CVE-2024-26859", "CVE-2024-26876", "CVE-2024-26878", "CVE-2024-26883", "CVE-2024-26884", "CVE-2024-26898", "CVE-2024-26901", "CVE-2024-26903", "CVE-2024-26907", "CVE-2024-26922", "CVE-2024-26929", "CVE-2024-26930", "CVE-2024-26931", "CVE-2024-26948", "CVE-2024-26993", "CVE-2024-27008", "CVE-2024-27013", "CVE-2024-27014", "CVE-2024-27043", "CVE-2024-27046", "CVE-2024-27054", "CVE-2024-27072", "CVE-2024-27073", "CVE-2024-27074", "CVE-2024-27075", "CVE-2024-27078", "CVE-2024-27388");
  script_tag(name:"creation_date", value:"2024-05-15 04:25:19 +0000 (Wed, 15 May 2024)");
  script_version("2024-05-24T19:38:34+0000");
  script_tag(name:"last_modification", value:"2024-05-24 19:38:34 +0000 (Fri, 24 May 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-23 19:10:49 +0000 (Thu, 23 May 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1643-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1643-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241643-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:1643-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security bugfixes.
The following security bugs were fixed:

CVE-2019-25160: Fixed out-of-bounds memory accesses in netlabel (bsc#1220394).
CVE-2020-36312: Fixed an issue in virt/kvm/kvm_main.c that had a kvm_io_bus_unregister_dev memory leak upon a kmalloc failure (bsc#1184509).
CVE-2021-23134: Fixed a use-after-free issue in nfc sockets (bsc#1186060).
CVE-2021-46904: Fixed NULL pointer dereference during tty device unregistration (bsc#1220416).
CVE-2021-46905: Fixed NULL pointer dereference on disconnect regression (bsc#1220418).
CVE-2021-46909: Fixed a PCI interrupt mapping in ARM footbridge (bsc#1220442).
CVE-2021-46938: Fixed a double free of blk_mq_tag_set in dev remove after table load fails in dm rq (bsc#1220554).
CVE-2021-46939: Fixed a denial of service in trace_clock_global() in tracing (bsc#1220580).
CVE-2021-46941: Fixed core softreset when switch mode in usb dwc3 (bsc#1220628).
CVE-2021-46950: Fixed a data corruption bug in raid1 arrays using bitmaps in md/raid1 (bsc#1220662).
CVE-2021-46955: Fixed an out-of-bounds read with openvswitch, when fragmenting IPv4 packets (bsc#1220513).
CVE-2021-46958: Fixed a race between transaction aborts and fsyncs leading to use-after-free in btrfs (bsc#1220521).
CVE-2021-46960: Fixed a warning on smb2_get_enc_key in cifs (bsc#1220528).
CVE-2021-46963: Fixed crash in qla2xxx_mqueuecommand() (bsc#1220536).
CVE-2021-46964: Fixed unreserved extra IRQ vectors in qla2xxx (bsc#1220538).
CVE-2021-46966: Fixed potential use-after-free issue in cm_write() (bsc#1220572).
CVE-2021-46981: Fixed a NULL pointer in flush_workqueue in nbd (bsc#1220611).
CVE-2021-46988: Fixed release page in error path to avoid BUG_ON (bsc#1220706).
CVE-2021-46990: Fixed a denial of service when toggling entry flush barrier in powerpc/64s (bsc#1220743).
CVE-2021-46998: Fixed an use after free bug in enic_hard_start_xmit in ethernet/enic (bsc#1220625).
CVE-2021-47006: Fixed wrong check in overflow_handler hook in ARM 9064/1 hw_breakpoint (bsc#1220751).
CVE-2021-47015: Fixed a RX consumer index logic in the error path in bnxt_rx_pkt() in bnxt_en (bsc#1220794).
CVE-2021-47024: Fixed possible memory leak in vsock/virtio when closing socket (bsc#1220637).
CVE-2021-47034: Fixed a kernel memory fault for pte update on radix in powerpc/64s (bsc#1220687).
CVE-2021-47045: Fixed a null pointer dereference in lpfc_prep_els_iocb() in scsi lpfc (bsc#1220640).
CVE-2021-47049: Fixed an after free in __vmbus_open() in hv vmbus (bsc#1220692).
CVE-2021-47055: Fixed missing permissions for locking and badblock ioctls in mtd (bsc#1220768).
CVE-2021-47056: Fixed a user-memory-access error on vf2pf_lock in crypto (bsc#1220769).
CVE-2021-47060: Fixed a bug in KVM by stop looking for coalesced MMIO zones if the bus is destroyed (bsc#1220742).
CVE-2021-47061: Fixed a bug in KVM by destroy I/O bus devices on ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.182.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.182.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.182.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.182.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.182.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.182.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.182.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.182.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.182.1", rls:"SLES12.0SP5"))) {
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
