# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1247");
  script_cve_id("CVE-2017-15124", "CVE-2017-18043", "CVE-2017-9330");
  script_tag(name:"creation_date", value:"2020-01-23 11:18:44 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-06 14:54:57 +0000 (Tue, 06 Feb 2018)");

  script_name("Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2018-1247)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.5\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2018-1247");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2018-1247");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu-kvm' package(s) announced via the EulerOS-SA-2018-1247 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Integer overflow in the macro ROUND_UP (n, d) in Quick Emulator (Qemu) allows a user to cause a denial of service (Qemu process crash).(CVE-2017-18043)

QEMU (aka Quick Emulator) before 2.9.0, when built with the USB OHCI Emulation support, allows local guest OS users to cause a denial of service (infinite loop) by leveraging an incorrect return value, a different vulnerability than CVE-2017-6505.(CVE-2017-9330)

VNC server implementation in Quick Emulator (QEMU) 2.11.0 and older was found to be vulnerable to an unbounded memory allocation issue, as it did not throttle the framebuffer updates sent to its client. If the client did not consume these updates, VNC server allocates growing memory to hold onto this data. A malicious remote VNC client could use this flaw to cause DoS to the server host.(CVE-2017-15124)");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Huawei EulerOS Virtualization 2.5.0.");

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

if(release == "EULEROSVIRT-2.5.0") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.6.0~B037", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~2.6.0~B037", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~2.6.0~B037", rls:"EULEROSVIRT-2.5.0"))) {
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
