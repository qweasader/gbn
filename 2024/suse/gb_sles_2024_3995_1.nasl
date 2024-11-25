# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3995.1");
  script_cve_id("CVE-2024-21820", "CVE-2024-21853", "CVE-2024-23918", "CVE-2024-23984", "CVE-2024-24968");
  script_tag(name:"creation_date", value:"2024-11-18 04:17:30 +0000 (Mon, 18 Nov 2024)");
  script_version("2024-11-19T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-11-19 05:05:41 +0000 (Tue, 19 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3995-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3995-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243995-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2024:3995-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

Intel CPU Microcode was updated to the 20241112 release (bsc#1233313)
CVE-2024-21853: Faulty finite state machines (FSMs) in the hardware logic in some 4th and 5th Generation Intel Xeon Processors may allow an authorized user to potentially enable denial of service via local access.
CVE-2024-23918: Improper conditions check in some Intel Xeon processor memory controller configurations when using Intel SGX may allow a privileged user to potentially enable escalation of privilege via local access.
CVE-2024-21820: Incorrect default permissions in some Intel Xeon processor memory controller configurations when using Intel SGX may allow a privileged user to potentially enable escalation of privilege via local access.
CVE-2024-24968: Improper finite state machines (FSMs) in hardware logic in some Intel Processors may allow an privileged user to potentially enable a denial of service via local access.
CVE-2024-23984: Observable discrepancy in RAPL interface for some Intel Processors may allow a privileged user to potentially enable information disclosure via local access.

Update for functional issues.
 New Platforms:
 <pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe> New Ver <pipe> Products
 <pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 Updated Platforms:
 <pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe> New Ver <pipe> Products
 <pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> ADL <pipe> C0 <pipe> 06-97-02/07 <pipe> 00000036 <pipe> 00000037 <pipe> Core Gen12
 <pipe> ADL <pipe> H0 <pipe> 06-97-05/07 <pipe> 00000036 <pipe> 00000037 <pipe> Core Gen12
 <pipe> ADL <pipe> L0 <pipe> 06-9a-03/80 <pipe> 00000434 <pipe> 00000435 <pipe> Core Gen12
 <pipe> ADL <pipe> R0 <pipe> 06-9a-04/80 <pipe> 00000434 <pipe> 00000435 <pipe> Core Gen12
 <pipe> EMR-SP <pipe> A0 <pipe> 06-cf-01/87 <pipe> 21000230 <pipe> 21000283 <pipe> Xeon Scalable Gen5
 <pipe> EMR-SP <pipe> A1 <pipe> 06-cf-02/87 <pipe> 21000230 <pipe> 21000283 <pipe> Xeon Scalable Gen5
 <pipe> MTL <pipe> C0 <pipe> 06-aa-04/e6 <pipe> 0000001f <pipe> 00000020 <pipe> Core(tm) Ultra Processor
 <pipe> RPL-H/P/PX 6+8 <pipe> J0 <pipe> 06-ba-02/e0 <pipe> 00004122 <pipe> 00004123 <pipe> Core Gen13
 <pipe> RPL-HX/S <pipe> C0 <pipe> 06-bf-02/07 <pipe> 00000036 <pipe> 00000037 <pipe> Core Gen13/Gen14
 <pipe> RPL-S <pipe> H0 <pipe> 06-bf-05/07 <pipe> 00000036 <pipe> 00000037 <pipe> Core Gen13/Gen14
 <pipe> RPL-U 2+8 <pipe> Q0 <pipe> 06-ba-03/e0 <pipe> 00004122 <pipe> 00004123 <pipe> Core Gen13
 <pipe> SPR-SP <pipe> E3 <pipe> 06-8f-06/87 <pipe> 2b0005c0 <pipe> 2b000603 <pipe> Xeon Scalable Gen4
 <pipe> SPR-SP <pipe> E4/S2 <pipe> 06-8f-07/87 <pipe> 2b0005c0 <pipe> 2b000603 <pipe> Xeon Scalable Gen4
 <pipe> SPR-SP <pipe> E5/S3 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20241112~146.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debuginfo", rpm:"ucode-intel-debuginfo~20241112~146.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debugsource", rpm:"ucode-intel-debugsource~20241112~146.1", rls:"SLES12.0SP5"))) {
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
