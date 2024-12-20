# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.880760");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:1289");
  script_cve_id("CVE-2008-2079", "CVE-2008-3963", "CVE-2008-4456", "CVE-2009-2446");
  script_name("CentOS Update for mysql CESA-2009:1289 centos5 i386");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016144.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"mysql on CentOS 5");
  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. It consists of
  the MySQL server daemon (mysqld) and many client programs and libraries.

  MySQL did not correctly check directories used as arguments for the DATA
  DIRECTORY and INDEX DIRECTORY directives. Using this flaw, an authenticated
  attacker could elevate their access privileges to tables created by other
  database users. Note: This attack does not work on existing tables. An
  attacker can only elevate their access to another user's tables as the
  tables are created. As well, the names of these created tables need to be
  predicted correctly for this attack to succeed. (CVE-2008-2079)

  A flaw was found in the way MySQL handles an empty bit-string literal. A
  remote, authenticated attacker could crash the MySQL server daemon (mysqld)
  if they used an empty bit-string literal in an SQL statement. This issue
  only caused a temporary denial of service, as the MySQL daemon was
  automatically restarted after the crash. (CVE-2008-3963)

  An insufficient HTML entities quoting flaw was found in the mysql command
  line client's HTML output mode. If an attacker was able to inject arbitrary
  HTML tags into data stored in a MySQL database, which was later retrieved
  using the mysql command line client and its HTML output mode, they could
  perform a cross-site scripting (XSS) attack against victims viewing the
  HTML output in a web browser. (CVE-2008-4456)

  Multiple format string flaws were found in the way the MySQL server logs
  user commands when creating and deleting databases. A remote, authenticated
  attacker with permissions to CREATE and DROP databases could use these
  flaws to formulate a specifically-crafted SQL command that would cause a
  temporary denial of service (open connections to mysqld are terminated).
  (CVE-2009-2446)

  Note: To exploit the CVE-2009-2446 flaws, the general query log (the mysqld
  '--log' command line option or the 'log' option in '/etc/my.cnf') must be
  enabled. This logging is not enabled by default.

  This update also fixes multiple bugs. Details regarding these bugs can be
  found in the Red Hat Enterprise Linux 5.4 Technical Notes. You can find a
  link to the Technical Notes in the References section of this errata.

  Note: These updated packages upgrade MySQL to version 5.0.77 to incorporate
  numerous upstream bug fixes.

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.77~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.77~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.77~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.77~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.77~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
