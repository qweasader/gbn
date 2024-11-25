# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1554");
  script_cve_id("CVE-2014-0001", "CVE-2014-6507", "CVE-2015-3152", "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0600", "CVE-2016-0606", "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0616", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-5612", "CVE-2016-5626", "CVE-2017-3302");
  script_tag(name:"creation_date", value:"2020-01-23 12:13:35 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-16 14:24:57 +0000 (Thu, 16 Feb 2017)");

  script_name("Huawei EulerOS: Security Advisory for mariadb (EulerOS-SA-2019-1554)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1554");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1554");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'mariadb' package(s) announced via the EulerOS-SA-2019-1554 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified vulnerability in Oracle MySQL 5.5.48 and earlier, 5.6.29 and earlier, and 5.7.11 and earlier and MariaDB before 5.5.49, 10.0.x before 10.0.25, and 10.1.x before 10.1.14 allows local users to affect confidentiality via vectors related to DML.(CVE-2016-0643)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 and MariaDB before 5.5.47, 10.0.x before 10.0.23, and 10.1.x before 10.1.10 allows remote authenticated users to affect availability via vectors related to UDF.(CVE-2016-0608)

Unspecified vulnerability in Oracle MySQL 5.5.47 and earlier, 5.6.28 and earlier, and 5.7.10 and earlier and MariaDB before 5.5.48, 10.0.x before 10.0.24, and 10.1.x before 10.1.12 allows local users to affect availability via vectors related to DDL.(CVE-2016-0644)

Unspecified vulnerability in Oracle MySQL Server 5.5.39 and earlier, and 5.6.20 and earlier, allows remote authenticated users to affect confidentiality, integrity, and availability via vectors related to SERVER:DML.(CVE-2014-6507)

Unspecified vulnerability in Oracle MySQL 5.5.47 and earlier, 5.6.28 and earlier, and 5.7.10 and earlier and MariaDB before 5.5.48, 10.0.x before 10.0.24, and 10.1.x before 10.1.12 allows local users to affect availability via vectors related to DML.(CVE-2016-0646)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 and MariaDB before 5.5.47, 10.0.x before 10.0.23, and 10.1.x before 10.1.10 allows remote authenticated users to affect availability via unknown vectors related to InnoDB.(CVE-2016-0600)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier, 5.6.27 and earlier, and 5.7.9 and MariaDB before 5.5.47, 10.0.x before 10.0.23, and 10.1.x before 10.1.10 allows remote authenticated users to affect availability via unknown vectors related to Optimizer.(CVE-2016-0597)

Buffer overflow in client/mysql.cc in Oracle MySQL and MariaDB before 5.5.35 allows remote database servers to cause a denial of service (crash) and possibly execute arbitrary code via a long server version string.(CVE-2014-0001)

Unspecified vulnerability in Oracle MySQL 5.5.48 and earlier, 5.6.29 and earlier, and 5.7.11 and earlier and MariaDB before 5.5.49, 10.0.x before 10.0.25, and 10.1.x before 10.1.14 allows local users to affect availability via vectors related to PS.(CVE-2016-0648)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier and 5.6.27 and earlier and MariaDB before 5.5.47, 10.0.x before 10.0.23, and 10.1.x before 10.1.10 allows remote authenticated users to affect availability via vectors related to DML.(CVE-2016-0596)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier and MariaDB before 5.5.47, 10.0.x before 10.0.23, and 10.1.x before 10.1.10 allows remote authenticated users to affect availability via unknown vectors related to Optimizer.(CVE-2016-0616)

Unspecified vulnerability in Oracle MySQL ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mariadb' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~5.5.60~1", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-libs", rpm:"mariadb-libs~5.5.60~1", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server", rpm:"mariadb-server~5.5.60~1", rls:"EULEROSVIRT-3.0.1.0"))) {
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
