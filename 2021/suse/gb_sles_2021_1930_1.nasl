# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1930.1");
  script_cve_id("CVE-2020-24489", "CVE-2020-24511", "CVE-2020-24512", "CVE-2020-24513");
  script_tag(name:"creation_date", value:"2021-06-11 02:15:39 +0000 (Fri, 11 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-01 18:46:07 +0000 (Thu, 01 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1930-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1930-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211930-1/");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-0");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-0");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-0");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-0");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/637780");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/338848");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/613537");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/products/docs/processors/xe");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/processors/xeon/xeon-e7-v3-");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/processors/xeon/xeon-e5-v3-");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/products/docs/processors/co");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/products/docs/processors/co");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2021:1930-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

Updated to Intel CPU Microcode 20210608 release.

CVE-2020-24513: A domain bypass transient execution vulnerability was
 discovered on some Intel Atom processors that use a micro-architectural
 incident channel. (INTEL-SA-00465 bsc#1179833)

 See also:
[link moved to references] 0465.html

CVE-2020-24511: The IBRS feature to mitigate Spectre variant 2 transient
 execution side channel vulnerabilities may not fully prevent non-root
 (guest) branches from controlling the branch predictions of the root
 (host) (INTEL-SA-00464 bsc#1179836)

 See also [link moved to references] 0464.html)

CVE-2020-24512: Fixed trivial data value cache-lines such as all-zero
 value cache-lines may lead to changes in cache-allocation or write-back
 behavior for such cache-lines (bsc#1179837 INTEL-SA-00464)

 See also [link moved to references] 0464.html)

CVE-2020-24489: Fixed Intel VT-d device pass through potential local
 privilege escalation (INTEL-SA-00442 bsc#1179839)

 See also [link moved to references] 0442.html

Other fixes:

Update for functional issues. Refer to [Third Generation Intel Xeon
 Processor Scalable Family Specification
 Update]([link moved to references])for details.

Update for functional issues. Refer to [Second Generation Intel Xeon
 Processor Scalable Family Specification
 Update]([link moved to references]) for details.

Update for functional issues. Refer to [Intel Xeon Processor Scalable
 Family Specification
 Update]([link moved to references]) for details.

Update for functional issues. Refer to [Intel Xeon Processor D-1500,
 D-1500 NS and D-1600 NS Spec Update]([link moved to references]
 on/xeon-d-1500-specification-update.html) for details.

Update for functional issues. Refer to [Intel Xeon E7-8800 and E7-4800
 v3 Processor Specification Update]([link moved to references]
 spec-update.html) for details.

Update for functional issues. Refer to [Intel Xeon Processor E5 v3
 Product Family Specification Update]([link moved to references]
 spec-update.html?wapkw=processor+spec+update+e5) for details.

Update for functional issues. Refer to [10th Gen Intel Core Processor
 Families Specification Update]([link moved to references]
 re/10th-gen-core-families-specification-update.html) for details.

Update for functional issues. Refer to [8th and 9th Gen Intel Core
 Processor Family Spec Update]([link moved to references]
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20210525~13.90.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debuginfo", rpm:"ucode-intel-debuginfo~20210525~13.90.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debugsource", rpm:"ucode-intel-debugsource~20210525~13.90.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20210525~13.90.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debuginfo", rpm:"ucode-intel-debuginfo~20210525~13.90.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debugsource", rpm:"ucode-intel-debugsource~20210525~13.90.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20210525~13.90.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debuginfo", rpm:"ucode-intel-debuginfo~20210525~13.90.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debugsource", rpm:"ucode-intel-debugsource~20210525~13.90.1", rls:"SLES12.0SP4"))) {
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
