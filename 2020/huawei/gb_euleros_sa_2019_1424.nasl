# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1424");
  script_cve_id("CVE-2013-7345", "CVE-2014-0207", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-2270", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3538", "CVE-2014-3587", "CVE-2014-8117", "CVE-2014-9652", "CVE-2014-9653");
  script_tag(name:"creation_date", value:"2020-01-23 11:44:37 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Huawei EulerOS: Security Advisory for file (EulerOS-SA-2019-1424)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1424");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1424");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'file' package(s) announced via the EulerOS-SA-2019-1424 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial of service flaw was found in the File Information (fileinfo) extension rules for detecting AWK files. A remote attacker could use this flaw to cause a PHP application using fileinfo to consume an excessive amount of CPU.(CVE-2013-7345)

A denial of service flaw was found in the way the File Information (fileinfo) extension parsed certain Composite Document Format (CDF) files. A remote attacker could use this flaw to crash a PHP application using fileinfo via a specially crafted CDF file.(CVE-2014-3479)

An ouf-of-bounds read flaw was found in the way the file utility processed certain Pascal strings. A remote attacker could cause an application using the file utility (for example, PHP using the fileinfo module) to crash if it was used to identify the type of the attacker-supplied file.(CVE-2014-9652)

A denial of service flaw was found in the way the File Information (fileinfo) extension parsed certain Composite Document Format (CDF) files. A remote attacker could use this flaw to crash a PHP application using fileinfo via a specially crafted CDF file.(CVE-2014-0207)

A denial of service flaw was found in the way the File Information (fileinfo) extension parsed certain Composite Document Format (CDF) files. A remote attacker could use this flaw to crash a PHP application using fileinfo via a specially crafted CDF file.(CVE-2014-3480)

It was found that the fix for CVE-2012-1571 was incomplete, the File Information (fileinfo) extension did not correctly parse certain Composite Document Format (CDF) files. A remote attacker could use this flaw to crash a PHP application using fileinfo via a specially crafted CDF file.(CVE-2014-3587)

A buffer overflow flaw was found in the way the File Information (fileinfo) extension processed certain Pascal strings. A remote attacker able to make a PHP application using fileinfo convert a specially crafted Pascal string provided by an image file could cause that application to crash.(CVE-2014-3478)

Multiple flaws were found in the File Information (fileinfo) extension regular expression rules for detecting various files. A remote attacker could use either of these flaws to cause a PHP application using fileinfo to consume an excessive amount of CPU.(CVE-2014-3538)

A denial of service flaw was found in the way the File Information (fileinfo) extension parsed certain Composite Document Format (CDF) files. A remote attacker could use this flaw to crash a PHP application using fileinfo via a specially crafted CDF file.(CVE-2014-3487)

A denial of service flaw was found in the way the File Information (fileinfo) extension handled search rules. A remote attacker could use this flaw to cause a PHP application using fileinfo to crash or consume an excessive amount of CPU.(CVE-2014-2270)

A flaw was found in the way the File Information (fileinfo) extension parsed Executable and Linkable Format (ELF) files. A remote attacker could use ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'file' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"file", rpm:"file~5.11~33.eulerosv2r7", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"file-libs", rpm:"file-libs~5.11~33.eulerosv2r7", rls:"EULEROSVIRT-3.0.1.0"))) {
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
