# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1291");
  script_cve_id("CVE-2017-1000380", "CVE-2017-15299", "CVE-2017-16525", "CVE-2017-16526", "CVE-2017-16529", "CVE-2017-16530", "CVE-2017-16531", "CVE-2017-16532", "CVE-2017-16533", "CVE-2017-16534", "CVE-2017-16535", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16538", "CVE-2017-16643", "CVE-2017-16644", "CVE-2017-16645", "CVE-2017-16649", "CVE-2017-16650");
  script_tag(name:"creation_date", value:"2020-01-23 11:05:47 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-28 18:47:08 +0000 (Tue, 28 Nov 2017)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2017-1291)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1291");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2017-1291");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2017-1291 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in the key management subsystem of the Linux kernel. An update on an uninstantiated key could cause a kernel panic, leading to denial of service (DoS).(CVE-2017-15299)

The usb_serial_console_disconnect function in drivers/usb/serial/console.c in the Linux kernel before 4.13.8 allows local users to cause a denial of service (use-after-free and system crash) or possibly have unspecified other impact via a crafted USB device, related to disconnection and failed setup.(CVE-2017-16525)

drivers/uwb/uwbd.c in the Linux kernel before 4.13.6 allows local users to cause a denial of service (general protection fault and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16526)

drivers/usb/core/config.c in the Linux kernel before 4.13.6 allows local users to cause a denial of service (out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device, related to the USB_DT_INTERFACE_ASSOCIATION descriptor.(CVE-2017-16531)

The get_endpoints function in drivers/usb/misc/usbtest.c in the Linux kernel through 4.13.11 allows local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16532)

The usbhid_parse function in drivers/hid/usbhid/hid-core.c in the Linux kernel before 4.13.8 allows local users to cause a denial of service (out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16533)

The uas driver in the Linux kernel before 4.13.6 allows local users to cause a denial of service (out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device, related to drivers/usb/storage/uas-detect.h and drivers/usb/storage/uas.c.(CVE-2017-16530)

The usb_get_bos_descriptor function in drivers/usb/core/config.c in the Linux kernel before 4.13.10 allows local users to cause a denial of service (out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16535)

A flaw was found that sound/core/timer.c in the Linux kernel before 4.11.5 is vulnerable to a data race in the ALSA /dev/snd/timer driver resulting in local users being able to read information belonging to other users. Uninitialized memory contents may be disclosed when a read and an ioctl happen at the same time.(CVE-2017-1000380)

The imon_probe function in drivers/media/rc/imon.c in the Linux kernel through 4.13.11 allows local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16537)

drivers/media/usb/dvb-usb-v2/lmedm04.c in the Linux kernel through 4.13.11 allows local users to cause a denial of service (general protection fault and system crash) or possibly have ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~229.49.1.155", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~229.49.1.155", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.10.0~229.49.1.155", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~3.10.0~229.49.1.155", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~229.49.1.155", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~229.49.1.155", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~229.49.1.155", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~229.49.1.155", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~229.49.1.155", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~229.49.1.155", rls:"EULEROS-2.0SP1"))) {
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
