# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2352");
  script_cve_id("CVE-2018-16872", "CVE-2018-19364", "CVE-2018-19489", "CVE-2019-3812", "CVE-2019-6778");
  script_tag(name:"creation_date", value:"2020-01-23 12:47:54 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2019-2352)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.3\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2352");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2352");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu-kvm' package(s) announced via the EulerOS-SA-2019-2352 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In QEMU 3.0.0, tcp_emu in slirp/tcp_subr.c has a heap-based buffer overflow.(CVE-2019-6778)

A flaw was found in QEMU's Media Transfer Protocol (MTP). The code opening files in usb_mtp_get_object and usb_mtp_get_partial_object and directories in usb_mtp_object_readdir doesn't consider that the underlying filesystem may have changed since the time lstat(2) was called in usb_mtp_object_alloc, a classical TOCTTOU problem. An attacker with write access to the host filesystem, shared with a guest, can use this property to navigate the host filesystem in the context of the QEMU process and read any file the QEMU process has access to. Access to the filesystem may be local or via a network share protocol such as CIFS.(CVE-2018-16872)

hw/9pfs/cofile.c and hw/9pfs/9p.c in QEMU can modify an fid path while it is being accessed by a second thread, leading to (for example) a use-after-free outcome.(CVE-2018-19364)

v9fs_wstat in hw/9pfs/9p.c in QEMU allows guest OS users to cause a denial of service (crash) because of a race condition during file renaming.(CVE-2018-19489)

QEMU, through version 2.10 and through version 3.1.0, is vulnerable to an out-of-bounds read of up to 128 bytes in the hw/i2c/i2c-ddc.c:i2c_ddc() function. A local attacker with permission to execute i2c commands could exploit this to read stack memory of the qemu process on the host.(CVE-2019-3812)");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.3.0.");

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

if(release == "EULEROSVIRTARM64-3.0.3.0") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.8.1~30.092", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.8.1~30.092", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~2.8.1~30.092", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~2.8.1~30.092", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
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
