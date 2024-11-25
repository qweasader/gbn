# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3095.1");
  script_cve_id("CVE-2023-42667", "CVE-2023-49141", "CVE-2024-24853", "CVE-2024-24980", "CVE-2024-25939");
  script_tag(name:"creation_date", value:"2024-09-04 04:26:54 +0000 (Wed, 04 Sep 2024)");
  script_version("2024-09-04T05:16:32+0000");
  script_tag(name:"last_modification", value:"2024-09-04 05:16:32 +0000 (Wed, 04 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3095-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3095-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243095-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2024:3095-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

Intel CPU Microcode was updated to the 20240813 release (bsc#1229129)
CVE-2024-24853: Security updates for INTEL-SA-01083 CVE-2024-25939: Security updates for INTEL-SA-01118 CVE-2024-24980: Security updates for INTEL-SA-01100 CVE-2023-42667: Security updates for INTEL-SA-01038 CVE-2023-49141: Security updates for INTEL-SA-01046
 Other issues fixed:
Update for functional issues. Refer to Intel Core Ultra Processor for details.
Update for functional issues. Refer to 3rd Generation Intel Xeon Processor Scalable Family Specification Update for details.
Update for functional issues. Refer to 3rd Generation Intel Xeon Scalable Processors Specification Update for details.
Update for functional issues. Refer to 2nd Generation Intel Xeon Processor Scalable Family Specification Update for details Update for functional issues. Refer to Intel Xeon D-2700 Processor Specification Update for details.
Update for functional issues. Refer to Intel Xeon E-2300 Processor Specification Update for details.
Update for functional issues. Refer to 13th Generation Intel Core Processor Specification Update for details.
Update for functional issues. Refer to 12th Generation Intel Core Processor Family for details.
Update for functional issues. Refer to 11th Gen Intel Core Processor Specification Update for details.
Update for functional issues. Refer to 10th Gen Intel Core Processor Families Specification Update for details.
Update for functional issues. Refer to 10th Generation Intel Core Processor Specification Update for details.
Update for functional issues. Refer to 8th and 9th Generation Intel Core Processor Family Spec Update for details.
Update for functional issues. Refer to 8th Generation Intel Core Processor Families Specification Update for details.
Update for functional issues. Refer to 7th and 8th Generation Intel Core Processor Specification Update for details.
Update for functional issues. Refer to Intel Processors and Intel Core i3 N-Series for details.

Update for functional issues. Refer to Intel Atom x6000E Series, and Intel Pentium and Celeron N and J Series Processors for Internet of Things (IoT) Applications for details.
 Updated Platforms:
 <pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe> New Ver <pipe> Products
 <pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> AML-Y22 <pipe> H0 <pipe> 06-8e-09/10 <pipe> 000000f4 <pipe> 000000f6 <pipe> Core Gen8 Mobile
 <pipe> AML-Y42 <pipe> V0 <pipe> 06-8e-0c/94 <pipe> 000000fa <pipe> 000000fc <pipe> Core Gen10 Mobile
 <pipe> CFL-H <pipe> R0 <pipe> 06-9e-0d/22 <pipe> 000000fc <pipe> 00000100 <pipe> Core Gen9 Mobile
 <pipe> CFL-H/S <pipe> P0 <pipe> 06-9e-0c/22 <pipe> 000000f6 <pipe> 000000f8 <pipe> Core Gen9
 <pipe> CFL-H/S/E3 <pipe> U0 <pipe> 06-9e-0a/22 <pipe> 000000f6 <pipe> 000000f8 <pipe> Core ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro 5.5, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20240813~150200.44.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20240813~150200.44.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20240813~150200.44.1", rls:"SLES15.0SP4"))) {
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
