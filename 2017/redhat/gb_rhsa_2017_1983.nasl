# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871864");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-08-04 12:47:49 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2017-7484", "CVE-2017-7486");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for postgresql RHSA-2017:1983-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"PostgreSQL is an advanced object-relational
  database management system (DBMS). The following packages have been upgraded to
  a later upstream version: postgresql (9.2.21). (BZ#1449706) Security Fix(es): *
  It was found that some selectivity estimation functions did not check user
  privileges before providing information from pg_statistic, possibly leaking
  information. A non-administrative database user could use this flaw to steal
  some information from tables they are otherwise not allowed to access.
  (CVE-2017-7484) * It was found that the pg_user_mappings view could disclose
  information about user mappings to a foreign database to non-administrative
  database users. A database user with USAGE privilege for this mapping could,
  when querying the view, obtain user mapping data, such as the username and
  password used to connect to the foreign database. (CVE-2017-7486) Red Hat would
  like to thank the PostgreSQL project for reporting these issues. Upstream
  acknowledges Robert Haas as the original reporter of CVE-2017-7484 and Andrew
  Wheelwright as the original reporter of CVE-2017-7486. Additional Changes: For
  detailed information on changes in this release, see the Red Hat Enterprise
  Linux 7.4 Release Notes linked from the References section.");
  script_tag(name:"affected", value:"postgresql on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2017:1983-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00023.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~9.2.21~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~9.2.21~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-debuginfo", rpm:"postgresql-debuginfo~9.2.21~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~9.2.21~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~9.2.21~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~9.2.21~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~9.2.21~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~9.2.21~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~9.2.21~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~9.2.21~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~9.2.21~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}