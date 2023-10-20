# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0568.1");
  script_cve_id("CVE-2022-21216", "CVE-2022-33196", "CVE-2022-38090");
  script_tag(name:"creation_date", value:"2023-03-28 13:04:06 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-06-20T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:26 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-28 19:42:00 +0000 (Tue, 28 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0568-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0568-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230568-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2023:0568-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:
Updated to Intel CPU Microcode 20230214 release.
Security issues fixed:

CVE-2022-38090: Security updates for INTEL-SA-00767 (bsc#1208275)
CVE-2022-33196: Security updates for INTEL-SA-00738 (bsc#1208276)

CVE-2022-21216: Security updates for INTEL-SA-00700 (bsc#1208277)


New Platforms:


<pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe> New Ver <pipe> Products
 <pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> SPR-SP <pipe> E2 <pipe> 06-8f-05/87 <pipe> <pipe> 2b000181 <pipe> Xeon Scalable Gen4
 <pipe> SPR-SP <pipe> E3 <pipe> 06-8f-06/87 <pipe> <pipe> 2b000181 <pipe> Xeon Scalable Gen4
 <pipe> SPR-SP <pipe> E4 <pipe> 06-8f-07/87 <pipe> <pipe> 2b000181 <pipe> Xeon Scalable Gen4
 <pipe> SPR-SP <pipe> E5 <pipe> 06-8f-08/87 <pipe> <pipe> 2b000181 <pipe> Xeon Scalable Gen4
 <pipe> SPR-HBM <pipe> B3 <pipe> 06-8f-08/10 <pipe> <pipe> 2c000170 <pipe> Xeon Max
 <pipe> RPL-P 6+8 <pipe> J0 <pipe> 06-ba-02/07 <pipe> <pipe> 0000410e <pipe> Core Gen13
 <pipe> RPL-H 6+8 <pipe> J0 <pipe> 06-ba-02/07 <pipe> <pipe> 0000410e <pipe> Core Gen13
 <pipe> RPL-U 2+8 <pipe> Q0 <pipe> 06-ba-02/07 <pipe> <pipe> 0000410e <pipe> Core Gen13

Updated Platforms:

<pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe> New Ver <pipe> Products
 <pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> ADL <pipe> C0 <pipe> 06-97-02/07 <pipe> 00000026 <pipe> 0000002c <pipe> Core Gen12
 <pipe> ADL <pipe> C0 <pipe> 06-97-05/07 <pipe> 00000026 <pipe> 0000002c <pipe> Core Gen12
 <pipe> ADL <pipe> C0 <pipe> 06-bf-02/07 <pipe> 00000026 <pipe> 0000002c <pipe> Core Gen12
 <pipe> ADL <pipe> C0 <pipe> 06-bf-05/07 <pipe> 00000026 <pipe> 0000002c <pipe> Core Gen12
 <pipe> ADL <pipe> L0 <pipe> 06-9a-03/80 <pipe> 00000424 <pipe> 00000429 <pipe> Core Gen12
 <pipe> ADL <pipe> L0 <pipe> 06-9a-04/80 <pipe> 00000424 <pipe> 00000429 <pipe> Core Gen12
 <pipe> CLX-SP <pipe> B0 <pipe> 06-55-06/bf <pipe> 04003302 <pipe> 04003303 <pipe> Xeon Scalable Gen2
 <pipe> CLX-SP <pipe> B1 <pipe> 06-55-07/bf <pipe> 05003302 <pipe> 05003303 <pipe> Xeon Scalable Gen2
 <pipe> CPX-SP <pipe> A1 <pipe> 06-55-0b/bf <pipe> 07002501 <pipe> 07002503 <pipe> Xeon Scalable Gen3
 <pipe> GLK <pipe> B0 <pipe> 06-7a-01/01 <pipe> 0000003c <pipe> 0000003e <pipe> Pentium Silver N/J5xxx, Celeron N/J4xxx
 <pipe> GLK-R <pipe> R0 <pipe> 06-7a-08/01 <pipe> 00000020 <pipe> 00000022 <pipe> Pentium J5040/N5030, Celeron J4125/J4025/N4020/N4120
 <pipe> ICL-D <pipe> B0 <pipe> 06-6c-01/10 <pipe> 01000201 <pipe> 01000211 <pipe> Xeon D-17xx, D-27xx
 <pipe> ICL-U/Y <pipe> D1 <pipe> 06-7e-05/80 <pipe> 000000b6 <pipe> 000000b8 <pipe> Core Gen10 Mobile
 <pipe> ICX-SP <pipe> D0 <pipe> 06-6a-06/87 <pipe> 0d000375 <pipe> 0d000389 <pipe> Xeon Scalable Gen3
 <pipe> JSL <pipe> ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Enterprise Storage 7, SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Real Time 15-SP3, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Manager Proxy 4.2, SUSE Manager Retail Branch Server 4.2, SUSE Manager Server 4.2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20230214~150200.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20230214~150200.21.1", rls:"SLES15.0SP3"))) {
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
