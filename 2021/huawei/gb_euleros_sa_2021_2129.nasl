# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2129");
  script_cve_id("CVE-2016-9798", "CVE-2016-9800", "CVE-2016-9801", "CVE-2016-9802", "CVE-2016-9804", "CVE-2016-9917", "CVE-2016-9918");
  script_tag(name:"creation_date", value:"2021-07-07 08:42:40 +0000 (Wed, 07 Jul 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-12 13:29:00 +0000 (Fri, 12 Apr 2019)");

  script_name("Huawei EulerOS: Security Advisory for bluez (EulerOS-SA-2021-2129)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.2\.2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2129");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2129");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'bluez' package(s) announced via the EulerOS-SA-2021-2129 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In BlueZ 5.42, a use-after-free was identified in 'conf_opt' function in 'tools/parser/l2cap.c' source file. This issue can be triggered by processing a corrupted dump file and will result in hcidump crash.(CVE-2016-9798)

In BlueZ 5.42, a buffer overflow was observed in 'pin_code_reply_dump' function in 'tools/parser/hci.c' source file. The issue exists because 'pin' array is overflowed by supplied parameter due to lack of boundary checks on size of the buffer from frame 'pin_code_reply_cp *cp' parameter.(CVE-2016-9800)

In BlueZ 5.42, a buffer overflow was observed in 'set_ext_ctrl' function in 'tools/parser/l2cap.c' source file when processing corrupted dump file.(CVE-2016-9801)

In BlueZ 5.42, a buffer over-read was identified in 'l2cap_packet' function in 'monitor/packet.c' source file. This issue can be triggered by processing a corrupted dump file and will result in btmon crash.(CVE-2016-9802)

In BlueZ 5.42, a buffer overflow was observed in 'commands_dump' function in 'tools/parser/csr.c' source file. The issue exists because 'commands' array is overflowed by supplied parameter due to lack of boundary checks on size of the buffer from frame 'frm->ptr' parameter. This issue can be triggered by processing a corrupted dump file and will result in hcidump crash.(CVE-2016-9804)

In BlueZ 5.42, a buffer overflow was observed in 'read_n' function in 'tools/hcidump.c' source file. This issue can be triggered by processing a corrupted dump file and will result in hcidump crash.(CVE-2016-9917)

In BlueZ 5.42, an out-of-bounds read was identified in 'packet_hexdump' function in 'monitor/packet.c' source file. This issue can be triggered by processing a corrupted dump file and will result in btmon crash.(CVE-2016-9918)");

  script_tag(name:"affected", value:"'bluez' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

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

if(release == "EULEROSVIRT-3.0.2.2") {

  if(!isnull(res = isrpmvuln(pkg:"bluez-libs", rpm:"bluez-libs~5.44~4.h2.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.2"))) {
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
