# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2518");
  script_cve_id("CVE-2021-46657", "CVE-2021-46661", "CVE-2021-46662", "CVE-2021-46663", "CVE-2021-46665", "CVE-2021-46666", "CVE-2021-46667", "CVE-2021-46668", "CVE-2022-27383", "CVE-2022-27386", "CVE-2022-27455", "CVE-2022-27457", "CVE-2022-31624");
  script_tag(name:"creation_date", value:"2022-10-10 07:55:28 +0000 (Mon, 10 Oct 2022)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-21 13:54:58 +0000 (Thu, 21 Apr 2022)");

  script_name("Huawei EulerOS: Security Advisory for mariadb (EulerOS-SA-2022-2518)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2518");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-2518");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'mariadb' package(s) announced via the EulerOS-SA-2022-2518 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MariaDB Server v10.7 and below was discovered to contain a segmentation fault via the component sql/sql_class.cc.(CVE-2022-27386)

MariaDB Server v10.6.3 and below was discovered to contain an use-after-free in the component my_wildcmp_8bit_impl at /strings/ctype-simple.c.(CVE-2022-27455)

MariaDB Server v10.6.3 and below was discovered to contain an use-after-free in the component my_mb_wc_latin1 at /strings/ctype-latin1.c.(CVE-2022-27457)

MariaDB Server v10.6 and below was discovered to contain an use-after-free in the component my_strcasecmp_8bit, which is exploited via specially crafted SQL statements.(CVE-2022-27383)

MariaDB Server before 10.7 is vulnerable to Denial of Service. While executing the plugin/server_audit/server_audit.c method log_statement_ex, the held lock lock_bigbuffer is not released correctly, which allows local users to trigger a denial of service due to the deadlock.(CVE-2022-31624)

get_sort_by_table in MariaDB before 10.6.2 allows an application crash via certain subquery uses of ORDER BY.(CVE-2021-46657)

MariaDB through 10.5.9 allows a set_var.cc application crash via certain uses of an UPDATE statement in conjunction with a nested subquery.(CVE-2021-46662)

MariaDB through 10.5.13 allows a ha_maria::extra application crash via certain SELECT statements.(CVE-2021-46663)

MariaDB before 10.6.2 allows an application crash because of mishandling of a pushdown from a HAVING clause to a WHERE clause.(CVE-2021-46666)

MariaDB through 10.5.9 allows a sql_parse.cc application crash because of incorrect used_tables expectations.(CVE-2021-46665)

MariaDB through 10.5.9 allows an application crash via certain long SELECT DISTINCT statements that improperly interact with storage-engine resource limitations for temporary data structures.(CVE-2021-46668)

MariaDB through 10.5.9 allows an application crash in find_field_in_tables and find_order_in_list via an unused common table expression (CTE).(CVE-2021-46661)

MariaDB before 10.6.5 has a sql_lex.cc integer overflow, leading to an application crash.(CVE-2021-46667)");

  script_tag(name:"affected", value:"'mariadb' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

if(release == "EULEROSVIRT-3.0.6.6") {

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~5.5.66~1.h6.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~5.5.66~1.h6.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-devel", rpm:"mariadb-devel~5.5.66~1.h6.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-libs", rpm:"mariadb-libs~5.5.66~1.h6.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server", rpm:"mariadb-server~5.5.66~1.h6.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
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
