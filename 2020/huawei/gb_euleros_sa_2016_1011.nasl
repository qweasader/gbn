# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2016.1011");
  script_cve_id("CVE-2015-4792", "CVE-2015-4802", "CVE-2015-4815", "CVE-2015-4816", "CVE-2015-4819", "CVE-2015-4826", "CVE-2015-4830", "CVE-2015-4836", "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4870", "CVE-2015-4879", "CVE-2015-4913", "CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0600", "CVE-2016-0606", "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0616", "CVE-2016-2047");
  script_tag(name:"creation_date", value:"2020-01-23 10:37:28 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Huawei EulerOS: Security Advisory for mariadb (EulerOS-SA-2016-1011)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2016-1011");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1011");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'mariadb' package(s) announced via the EulerOS-SA-2016-1011 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that the MariaDB client library did not properly check host names against server identities noted in the X.509 certificates when establishing secure connections using TLS/SSL. A man-in-the-middle attacker could possibly use this flaw to impersonate a server to a client. (CVE-2016-2047)

This update fixes several vulnerabilities in the MariaDB database server. Information about these flaws can be found on the Oracle Critical Patch Update Advisory page, listed in the References section.(CVE-2015-4792, CVE-2015-4802, CVE-2015-4815, CVE-2015-4816, CVE-2015-4819, CVE-2015-4826, CVE-2015-4830, CVE-2015-4836, CVE-2015-4858, CVE-2015-4861, CVE-2015-4870, CVE-2015-4879, CVE-2015-4913, CVE-2016-0505, CVE-2016-0546, CVE-2016-0596, CVE-2016-0597, CVE-2016-0598, CVE-2016-0600, CVE-2016-0606, CVE-2016-0608, CVE-2016-0609, CVE-2016-0616)");

  script_tag(name:"affected", value:"'mariadb' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~5.5.47~1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~5.5.47~1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-devel", rpm:"mariadb-devel~5.5.47~1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-embedded", rpm:"mariadb-embedded~5.5.47~1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-libs", rpm:"mariadb-libs~5.5.47~1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server", rpm:"mariadb-server~5.5.47~1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-test", rpm:"mariadb-test~5.5.47~1", rls:"EULEROS-2.0SP1"))) {
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
