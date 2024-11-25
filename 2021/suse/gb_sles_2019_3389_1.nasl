# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3389.1");
  script_cve_id("CVE-2019-14901", "CVE-2019-15213", "CVE-2019-16746", "CVE-2019-19051", "CVE-2019-19066", "CVE-2019-19077", "CVE-2019-19332", "CVE-2019-19338", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19525", "CVE-2019-19526", "CVE-2019-19527", "CVE-2019-19528", "CVE-2019-19529", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19534", "CVE-2019-19535", "CVE-2019-19536", "CVE-2019-19537", "CVE-2019-19543");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-10 14:55:37 +0000 (Tue, 10 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3389-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3389-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193389-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:3389-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2019-16746: There was an issue in net/wireless/nl80211.c where the
 kernel did not check the length of variable elements in a beacon head,
 leading to a buffer overflow (bnc#1152107).

CVE-2019-19066: Fixed memory leak in the bfad_im_get_stats() function in
 drivers/scsi/bfa/bfad_attr.c that allowed attackers to cause a denial of
 service (memory consumption) by triggering bfa_port_get_stats() failures
 (bnc#1157303).

CVE-2019-19051: Fixed memory leak in the i2400m_op_rfkill_sw_toggle()
 function in drivers/net/wimax/i2400m/op-rfkill.c that allowed attackers
 to cause a denial of service (memory consumption) (bnc#1159024).

CVE-2019-19338: There was an incomplete fix for Transaction Asynchronous
 Abort (TAA) (bsc#1158954).

CVE-2019-19332: There was an OOB memory write via
 kvm_dev_ioctl_get_cpuid (bsc#1158827).

CVE-2019-19537: There was a race condition bug that could have been
 caused by a malicious USB device in the USB character device driver
 layer (bnc#1158904).

CVE-2019-19535: There was an info-leak bug that could have been caused
 by a malicious USB device in the
 drivers/net/can/usb/peak_usb/pcan_usb_fd.c driver (bnc#1158903).

CVE-2019-19527: There was a use-after-free bug that could have been
 caused by a malicious USB device in the drivers/hid/usbhid/hiddev.c
 driver (bnc#1158900).

CVE-2019-19526: There was a use-after-free bug that could have been
 caused by a malicious USB device in the drivers/nfc/pn533/usb.c driver
 (bnc#1158893).

CVE-2019-19533: There was an info-leak bug that could have been caused
 by a malicious USB device in the drivers/media/usb/ttusb-dec/ttusb_dec.c
 driver (bnc#1158834).

CVE-2019-19532: There were multiple out-of-bounds write bugs that could
 have been caused by a malicious USB device in the Linux kernel HID
 drivers (bnc#1158824).

CVE-2019-19523: There was a use-after-free bug that could have been
 caused by a malicious USB device in the drivers/usb/misc/adutux.c driver
 (bnc#1158823).

CVE-2019-15213: An issue was discovered in the Linux kernel, there was a
 use-after-free caused by a malicious USB device in the
 drivers/media/usb/dvb-usb/dvb-usb-init.c driver (bnc#1146544).

CVE-2019-19531: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/usb/misc/yurex.c driver
 (bnc#1158445).

CVE-2019-19543: There was a use-after-free in serial_ir_init_module() in
 drivers/media/rc/serial_ir.c (bnc#1158427).

CVE-2019-19525: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/net/ieee802154/atusb.c driver
 (bnc#1158417).

CVE-2019-19530: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/usb/class/cdc-acm.c driver
 (bnc#1158410).

CVE-2019-19536: There was an info-leak bug ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 12-SP5, SUSE Linux Enterprise Live Patching 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~122.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~122.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~122.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~122.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.12.1", rls:"SLES12.0SP5"))) {
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
