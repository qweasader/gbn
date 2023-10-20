# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2093.1");
  script_cve_id("CVE-2014-3672", "CVE-2016-3158", "CVE-2016-3159", "CVE-2016-3710", "CVE-2016-3960", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4952", "CVE-2016-4962", "CVE-2016-4963", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6258", "CVE-2016-6259", "CVE-2016-6351");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-14 19:54:00 +0000 (Mon, 14 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2093-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2093-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162093-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2016:2093-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen to version 4.5.3 fixes the several issues.
These security issues were fixed:
- CVE-2016-6258: Potential privilege escalation in PV guests (XSA-182)
 (bsc#988675).
- CVE-2016-6259: Missing SMAP whitelisting in 32-bit exception / event
 delivery (XSA-183) (bsc#988676).
- CVE-2016-5337: The megasas_ctrl_get_info function allowed local guest OS
 administrators to obtain sensitive host memory information via vectors
 related to reading device control information (bsc#983973).
- CVE-2016-5338: The (1) esp_reg_read and (2) esp_reg_write functions
 allowed local guest OS administrators to cause a denial of service (QEMU
 process crash) or execute arbitrary code on the host via vectors related
 to the information transfer buffer (bsc#983984).
- CVE-2016-5238: The get_cmd function in hw/scsi/esp.c might have allowed
 local guest OS administrators to cause a denial of service
 (out-of-bounds write and QEMU process crash) via vectors related to
 reading from the information transfer buffer in non-DMA mode
 (bsc#982960).
- CVE-2016-4453: The vmsvga_fifo_run function allowed local guest OS
 administrators to cause a denial of service (infinite loop and QEMU
 process crash) via a VGA command (bsc#982225).
- CVE-2016-4454: The vmsvga_fifo_read_raw function allowed local guest OS
 administrators to obtain sensitive host memory information or cause a
 denial of service (QEMU process crash) by changing FIFO registers and
 issuing a VGA command, which triggered an out-of-bounds read
 (bsc#982224).
- CVE-2016-5126: Heap-based buffer overflow in the iscsi_aio_ioctl
 function allowed local guest OS users to cause a denial of service (QEMU
 process crash) or possibly execute arbitrary code via a crafted iSCSI
 asynchronous I/O ioctl call (bsc#982286).
- CVE-2016-5105: Stack information leakage while reading configuration
 (bsc#982024).
- CVE-2016-5106: Out-of-bounds write while setting controller properties
 (bsc#982025).
- CVE-2016-5107: Out-of-bounds read in megasas_lookup_frame() function
 (bsc#982026).
- CVE-2016-4963: The libxl device-handling allowed local guest OS users
 with access to the driver domain to cause a denial of service
 (management tool confusion) by manipulating information in the backend
 directories in xenstore (bsc#979670).
- CVE-2016-4962: The libxl device-handling allowed local OS guest
 administrators to cause a denial of service (resource consumption or
 management facility confusion) or gain host OS privileges by
 manipulating information in guest controlled areas of xenstore
 (bsc#979620).
- CVE-2016-4952: Out-of-bounds access issue in pvsci_ring_init_msg/data
 routines (bsc#981276).
- CVE-2014-3672: The qemu implementation in libvirt Xen allowed local
 guest OS users to cause a denial of service (host disk consumption) by
 writing to stdout or stderr (bsc#981264).
- CVE-2016-4441: The get_cmd function in the 53C9X Fast SCSI Controller
 (FSC) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.5.3_08~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.5.3_08~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.5.3_08~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.5.3_08_k3.12.59_60.45~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.5.3_08_k3.12.59_60.45~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.5.3_08~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.5.3_08~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.5.3_08~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.5.3_08~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.5.3_08~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.5.3_08~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.5.3_08~17.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.5.3_08~17.1", rls:"SLES12.0SP1"))) {
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
