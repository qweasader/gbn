# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881225");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:51:56 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-2262", "CVE-2012-0075", "CVE-2012-0087", "CVE-2012-0101",
                "CVE-2012-0102", "CVE-2012-0112", "CVE-2012-0113", "CVE-2012-0114",
                "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0118", "CVE-2012-0119",
                "CVE-2012-0120", "CVE-2012-0484", "CVE-2012-0485", "CVE-2012-0490",
                "CVE-2012-0492");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_xref(name:"CESA", value:"2012:0105");
  script_name("CentOS Update for mysql CESA-2012:0105 centos6");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-February/018424.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-x.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"mysql on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. It consists of
  the MySQL server daemon (mysqld) and many client programs and libraries.

  This update fixes several vulnerabilities in the MySQL database server.
  Information about these flaws can be found on the Oracle Critical Patch
  Update Advisory page, listed in the References section. (CVE-2011-2262,
  CVE-2012-0075, CVE-2012-0087, CVE-2012-0101, CVE-2012-0102, CVE-2012-0112,
  CVE-2012-0113, CVE-2012-0114, CVE-2012-0115, CVE-2012-0116, CVE-2012-0118,
  CVE-2012-0119, CVE-2012-0120, CVE-2012-0484, CVE-2012-0485, CVE-2012-0490,
  CVE-2012-0492)

  These updated packages upgrade MySQL to version 5.1.61. Refer to the linked MySQL
  release notes for a full list of changes.

  All MySQL users should upgrade to these updated packages, which correct
  these issues. After installing this update, the MySQL server daemon
  (mysqld) will be restarted automatically.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.1.61~1.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.1.61~1.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.1.61~1.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-embedded", rpm:"mysql-embedded~5.1.61~1.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-embedded-devel", rpm:"mysql-embedded-devel~5.1.61~1.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-libs", rpm:"mysql-libs~5.1.61~1.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.1.61~1.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.1.61~1.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
