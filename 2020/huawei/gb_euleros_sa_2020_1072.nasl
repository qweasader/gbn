# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1072");
  script_cve_id("CVE-2017-16808", "CVE-2018-10103", "CVE-2018-10105", "CVE-2018-14461", "CVE-2018-14462", "CVE-2018-14463", "CVE-2018-14464", "CVE-2018-14465", "CVE-2018-14466", "CVE-2018-14467", "CVE-2018-14468", "CVE-2018-14469", "CVE-2018-14470", "CVE-2018-14880", "CVE-2018-14881", "CVE-2018-14882", "CVE-2018-16227", "CVE-2018-16228", "CVE-2018-16229", "CVE-2018-16230", "CVE-2018-16300", "CVE-2018-16301", "CVE-2018-16451", "CVE-2018-16452", "CVE-2018-19519", "CVE-2019-1010220", "CVE-2019-15166", "CVE-2019-15167");
  script_tag(name:"creation_date", value:"2020-01-23 13:18:58 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-11 23:15:00 +0000 (Fri, 11 Oct 2019)");

  script_name("Huawei EulerOS: Security Advisory for tcpdump (EulerOS-SA-2020-1072)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.5\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1072");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1072");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'tcpdump' package(s) announced via the EulerOS-SA-2020-1072 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"tcpdump.org tcpdump 4.9.2 is affected by: CWE-126: Buffer Over-read. The impact is: May expose Saved Frame Pointer, Return Address etc. on stack. The component is: line 234: 'ND_PRINT((ndo, '%s', buf)),', in function named 'print_prefix', in 'print-hncp.c'. The attack vector is: The victim must open a specially crafted pcap file.(CVE-2019-1010220)

In tcpdump 4.9.2, a stack-based buffer over-read exists in the print_prefix function of print-hncp.c via crafted packet data because of missing initialization.(CVE-2018-19519)

This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2019-15167)

lmp_print_data_link_subobjs() in print-lmp.c in tcpdump before 4.9.3 lacks certain bounds checks.(CVE-2019-15166)

The HNCP parser in tcpdump before 4.9.3 has a buffer over-read in print-hncp.c:print_prefix().(CVE-2018-16228)

The BGP parser in tcpdump before 4.9.3 allows stack consumption in print-bgp.c:bgp_attr_print() because of unlimited recursion.(CVE-2018-16300)

The SMB parser in tcpdump before 4.9.3 has stack exhaustion in smbutil.c:smb_fdata() via recursion.(CVE-2018-16452)

The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_attr_print() (MP_REACH_NLRI).(CVE-2018-16230)

libpcap before 1.9.1, as used in tcpdump before 4.9.3, has a buffer overflow and/or over-read because of errors in pcapng reading.(CVE-2018-16301)

The DCCP parser in tcpdump before 4.9.3 has a buffer over-read in print-dccp.c:dccp_print_option().(CVE-2018-16229)

The IEEE 802.11 parser in tcpdump before 4.9.3 has a buffer over-read in print-802_11.c for the Mesh Flags subfield.(CVE-2018-16227)

The ICMPv6 parser in tcpdump before 4.9.3 has a buffer over-read in print-icmp6.c.(CVE-2018-14882)

The SMB parser in tcpdump before 4.9.3 has buffer over-reads in print-smb.c:print_trans() for \MAILSLOT\BROWSE and \PIPE\LANMAN.(CVE-2018-16451)

The OSPFv3 parser in tcpdump before 4.9.3 has a buffer over-read in print-ospf6.c:ospf6_print_lshdr().(CVE-2018-14880)

tcpdump before 4.9.3 mishandles the printing of SMB data (issue 2 of 2).(CVE-2018-10105)

tcpdump before 4.9.3 mishandles the printing of SMB data (issue 1 of 2).(CVE-2018-10103)

The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_capabilities_print() (BGP_CAPCODE_MP).(CVE-2018-14467)

The VRRP parser in tcpdump before 4.9.3 has a buffer over-read in print-vrrp.c:vrrp_print().(CVE-2018-14463)

The LMP parser in tcpdump before 4.9.3 has a buffer over-read in print-lmp.c:lmp_print_data_link_subobjs().(CVE-2018-14464)

The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_capabilities_print() (BGP_CAPCODE_RESTART).(CVE-2018-14881)

The RSVP parser in tcpdump before 4.9.3 has a buffer over-read in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tcpdump' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.5.0.");

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

if(release == "EULEROSVIRTARM64-3.0.5.0") {

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.3~1.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
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
