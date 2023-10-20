# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881889");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-04 10:47:03 +0530 (Tue, 04 Mar 2014)");
  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063",
                "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("CentOS Update for postgresql CESA-2014:0211 centos6");

  script_tag(name:"affected", value:"postgresql on CentOS 6");
  script_tag(name:"insight", value:"PostgreSQL is an advanced object-relational database management system
(DBMS).

Multiple stack-based buffer overflow flaws were found in the date/time
implementation of PostgreSQL. An authenticated database user could provide
a specially crafted date/time value that, when processed, could cause
PostgreSQL to crash or, potentially, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2014-0063)

Multiple integer overflow flaws, leading to heap-based buffer overflows,
were found in various type input functions in PostgreSQL. An authenticated
database user could possibly use these flaws to crash PostgreSQL or,
potentially, execute arbitrary code with the permissions of the user
running PostgreSQL. (CVE-2014-0064)

Multiple potential buffer overflow flaws were found in PostgreSQL.
An authenticated database user could possibly use these flaws to crash
PostgreSQL or, potentially, execute arbitrary code with the permissions of
the user running PostgreSQL. (CVE-2014-0065)

It was found that granting an SQL role to a database user in a PostgreSQL
database without specifying the 'ADMIN' option allowed the grantee to
remove other users from their granted role. An authenticated database user
could use this flaw to remove a user from an SQL role which they were
granted access to. (CVE-2014-0060)

A flaw was found in the validator functions provided by PostgreSQL's
procedural languages (PLs). An authenticated database user could possibly
use this flaw to escalate their privileges. (CVE-2014-0061)

A race condition was found in the way the CREATE INDEX command performed
multiple independent lookups of a table that had to be indexed. An
authenticated database user could possibly use this flaw to escalate their
privileges. (CVE-2014-0062)

It was found that the chkpass extension of PostgreSQL did not check the
return value of the crypt() function. An authenticated database user could
possibly use this flaw to crash PostgreSQL via a null pointer dereference.
(CVE-2014-0066)

Red Hat would like to thank the PostgreSQL project for reporting these
issues. Upstream acknowledges Noah Misch as the original reporter of
CVE-2014-0060 and CVE-2014-0063, Heikki Linnakangas and Noah Misch as the
original reporters of CVE-2014-0064, Peter Eisentraut and Jozef Mlich as
the original reporters of CVE-2014-0065, Andres Freund as the original
reporter of CVE-2014-0061, Robert Haas and Andres Freund as the original
reporters of CVE-2014-0062, and Honza Horak and Bruce Momjian as the
original reporters of CVE-2014-0066.

These updated packages upgrade PostgreSQL to version 8.4.20, which fixes
these iss ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0211");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-February/020178.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
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

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.4.20~1.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~8.4.20~1.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~8.4.20~1.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~8.4.20~1.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~8.4.20~1.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~8.4.20~1.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~8.4.20~1.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~8.4.20~1.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~8.4.20~1.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~8.4.20~1.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
