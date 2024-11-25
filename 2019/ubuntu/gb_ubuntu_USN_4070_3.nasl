# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844137");
  script_cve_id("CVE-2019-2614", "CVE-2019-2627", "CVE-2019-2628", "CVE-2019-2737", "CVE-2019-2739", "CVE-2019-2740", "CVE-2019-2758", "CVE-2019-2805");
  script_tag(name:"creation_date", value:"2019-08-14 02:02:56 +0000 (Wed, 14 Aug 2019)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-25 15:23:03 +0000 (Thu, 25 Jul 2019)");

  script_name("Ubuntu: Security Advisory (USN-4070-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU19\.04");

  script_xref(name:"Advisory-ID", value:"USN-4070-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4070-3");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-27.html");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10317-changelog/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10317-release-notes/");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb-10.3' package(s) announced via the USN-4070-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4070-1 fixed multiple vulnerabilities in MySQL. This update provides the
corresponding fixes for CVE-2019-2737, CVE-2019-2739, CVE-2019-2740,
CVE-2019-2758, CVE-2019-2805, CVE-2019-2628, CVE-2019-2627, CVE-2019-2614 in
MariaDB 10.3.

Ubuntu 19.04 has been updated to MariaDB 10.3.17.

In addition to security fixes, the updated package contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:
[link moved to references]
[link moved to references]

Original advisory details:

 Multiple security issues were discovered in MySQL and this update includes
 a new upstream MySQL version to fix these issues.

 Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 19.04 have been updated to
 MySQL 5.7.27.

 In addition to security fixes, the updated packages contain bug fixes, new
 features, and possibly incompatible changes.

 Please see the following for more information:
 [link moved to references]
 [link moved to references]");

  script_tag(name:"affected", value:"'mariadb-10.3' package(s) on Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libmariadb-dev", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmariadb-dev-compat", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmariadb3", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmariadbclient-dev", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmariadbd-dev", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmariadbd19", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-backup", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-client", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-client-10.3", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-client-core-10.3", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-common", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-connect", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-cracklib-password-check", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-gssapi-client", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-gssapi-server", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-mroonga", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-oqgraph", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-rocksdb", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-spider", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-plugin-tokudb", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-server", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-server-10.3", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-server-core-10.3", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-test", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-test-data", ver:"1:10.3.17-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
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
