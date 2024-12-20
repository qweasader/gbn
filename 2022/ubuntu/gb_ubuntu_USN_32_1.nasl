# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2004.32.1");
  script_cve_id("CVE-2004-0836", "CVE-2004-0837", "CVE-2004-0956", "CVE-2004-0957");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-32-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-32-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-32-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-dfsg' package(s) announced via the USN-32-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the MySQL database
server.

Lukasz Wojtow discovered a potential buffer overflow in the function
mysql_real_connect(). A malicious name server could send specially
crafted DNS packages which might result in execution of arbitrary code
with the database server's privileges. However, it is believed that
this bug cannot be exploited with the C Standard library (glibc) that
Ubuntu uses. (CAN-2004-0836).

Dean Ellis noticed a flaw that allows an authorized MySQL user to
cause a denial of service (crash or hang) via concurrent execution of
certain statements (ALTER TABLE ... UNION=, FLUSH TABLES) on tables of
type MERGE (CAN-2004-0837)

Some query strings containing a double quote (like MATCH ... AGAINST
(' some ' query' IN BOOLEAN MODE) ) that did not have a matching
closing double quote caused a denial of service (server crash). Again,
this is only exploitable by authorized mysql users. (CAN-2004-0956)

If a user was granted privileges to a database with a name containing
an underscore ('_'), the user also gained the ability to grant
privileges to other databases with similar names. (CAN-2004-0957)");

  script_tag(name:"affected", value:"'mysql-dfsg' package(s) on Ubuntu 4.10.");

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

if(release == "UBUNTU4.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient-dev", ver:"4.0.20-2ubuntu1.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient12", ver:"4.0.20-2ubuntu1.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client", ver:"4.0.20-2ubuntu1.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common", ver:"4.0.20-2ubuntu1.1", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server", ver:"4.0.20-2ubuntu1.1", rls:"UBUNTU4.10"))) {
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
