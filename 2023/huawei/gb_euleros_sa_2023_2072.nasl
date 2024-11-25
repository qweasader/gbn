# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2072");
  script_cve_id("CVE-2022-20409", "CVE-2022-20422", "CVE-2022-20423", "CVE-2022-20568", "CVE-2022-20572", "CVE-2022-2196", "CVE-2022-2602", "CVE-2022-27672", "CVE-2022-3111", "CVE-2022-3114", "CVE-2022-3239", "CVE-2022-3303", "CVE-2022-3424", "CVE-2022-3435", "CVE-2022-3523", "CVE-2022-3524", "CVE-2022-3534", "CVE-2022-3542", "CVE-2022-3545", "CVE-2022-3566", "CVE-2022-3567", "CVE-2022-3577", "CVE-2022-3586", "CVE-2022-3606", "CVE-2022-3623", "CVE-2022-3625", "CVE-2022-3629", "CVE-2022-3707", "CVE-2022-3903", "CVE-2022-39188", "CVE-2022-39189", "CVE-2022-39190", "CVE-2022-41218", "CVE-2022-4129", "CVE-2022-41850", "CVE-2022-4269", "CVE-2022-42703", "CVE-2022-43750", "CVE-2022-4378", "CVE-2022-4662", "CVE-2022-4696", "CVE-2022-47929", "CVE-2022-47946", "CVE-2023-0045", "CVE-2023-0179", "CVE-2023-0240", "CVE-2023-0394", "CVE-2023-0461", "CVE-2023-0590", "CVE-2023-0597", "CVE-2023-1073", "CVE-2023-1074", "CVE-2023-1075", "CVE-2023-1076", "CVE-2023-1095", "CVE-2023-1118", "CVE-2023-1382", "CVE-2023-20928", "CVE-2023-23454", "CVE-2023-23455", "CVE-2023-23586", "CVE-2023-26545", "CVE-2023-28327", "CVE-2023-28328");
  script_tag(name:"creation_date", value:"2023-06-07 04:14:30 +0000 (Wed, 07 Jun 2023)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-13 14:12:08 +0000 (Fri, 13 Jan 2023)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2023-2072)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.11\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2072");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2023-2072");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2023-2072 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in Linux Kernel. It has been declared as problematic. This vulnerability affects the function vsock_connect of the file net/vmw_vsock/af_vsock.c of the component IPsec. The manipulation leads to memory leak. It is recommended to apply a patch to fix this issue. VDB-211930 is the identifier assigned to this vulnerability.(CVE-2022-3629)

A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects the function inet6_stream_ops/inet6_dgram_ops of the component IPv6 Handler. The manipulation leads to race condition. It is recommended to apply a patch to fix this issue. VDB-211090 is the identifier assigned to this vulnerability.(CVE-2022-3567)

drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-space client to corrupt the monitor's internal memory.(CVE-2022-43750)

In io_identity_cow of io_uring.c, there is a possible way to corrupt memory due to a use after free. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.(CVE-2022-20409)

A flaw was found in the Linux kernel. A race issue occurs between an io_uring request and the Unix socket garbage collector, allowing an attacker local privilege escalation.(CVE-2022-2602)

A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier VDB-211045 was assigned to this vulnerability.(CVE-2022-3545)

A vulnerability was found in Linux Kernel. It has been classified as critical. This affects the function devlink_param_set/devlink_param_get of the file net/core/devlink.c of the component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier VDB-211929 was assigned to this vulnerability.(CVE-2022-3625)

A vulnerability classified as critical has been found in Linux Kernel. Affected is the function btf_dump_name_dups of the file tools/lib/bpf/btf_dump.c of the component libbpf. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-211032.(CVE-2022-3534)

A vulnerability was found in Linux Kernel. It has been classified as problematic. This affects the function find_prog_by_sec_insn of the file tools/lib/bpf/libbpf.c of the component BPF. The manipulation leads to null pointer dereference. It is recommended to apply a patch to fix this issue. The identifier VDB-211749 was assigned to this vulnerability.(CVE-2022-3606)

A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.11.1.");

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

if(release == "EULEROSVIRT-2.11.1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~60.18.0.50.h815.eulerosv2r11", rls:"EULEROSVIRT-2.11.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~60.18.0.50.h815.eulerosv2r11", rls:"EULEROSVIRT-2.11.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~60.18.0.50.h815.eulerosv2r11", rls:"EULEROSVIRT-2.11.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~60.18.0.50.h815.eulerosv2r11", rls:"EULEROSVIRT-2.11.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~60.18.0.50.h815.eulerosv2r11", rls:"EULEROSVIRT-2.11.1"))) {
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
