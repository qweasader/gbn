# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.880663");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2010:0430");
  script_cve_id("CVE-2010-1169", "CVE-2010-1170");
  script_name("CentOS Update for postgresql84 CESA-2010:0430 centos5 i386");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-May/016654.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/8.4/static/release.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql84'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"postgresql84 on CentOS 5");
  script_tag(name:"insight", value:"PostgreSQL is an advanced object-relational database management system
  (DBMS). PL/Perl and PL/Tcl allow users to write PostgreSQL functions in the
  Perl and Tcl languages, and are installed in trusted mode by default. In
  trusted mode, certain operations, such as operating system level access,
  are restricted.

  A flaw was found in the way PostgreSQL enforced permission checks on
  scripts written in PL/Perl. If the PL/Perl procedural language was
  registered on a particular database, an authenticated database user running
  a specially-crafted PL/Perl script could use this flaw to bypass intended
  PL/Perl trusted mode restrictions, allowing them to run arbitrary Perl
  scripts with the privileges of the database server. (CVE-2010-1169)

  Red Hat would like to thank Tim Bunce for responsibly reporting the
  CVE-2010-1169 flaw.

  A flaw was found in the way PostgreSQL enforced permission checks on
  scripts written in PL/Tcl. If the PL/Tcl procedural language was registered
  on a particular database, an authenticated database user running a
  specially-crafted PL/Tcl script could use this flaw to bypass intended
  PL/Tcl trusted mode restrictions, allowing them to run arbitrary Tcl
  scripts with the privileges of the database server. (CVE-2010-1170)

  These packages upgrade PostgreSQL to version 8.4.4. Refer to the linked PostgreSQL
  Release Notes for a list of changes.

  All PostgreSQL users are advised to upgrade to these updated packages,
  which correct these issues. If the postgresql service is running, it will
  be automatically restarted after installing this update.");
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

  if ((res = isrpmvuln(pkg:"postgresql84", rpm:"postgresql84~8.4.4~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-contrib", rpm:"postgresql84-contrib~8.4.4~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-devel", rpm:"postgresql84-devel~8.4.4~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-docs", rpm:"postgresql84-docs~8.4.4~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-libs", rpm:"postgresql84-libs~8.4.4~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-plperl", rpm:"postgresql84-plperl~8.4.4~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-plpython", rpm:"postgresql84-plpython~8.4.4~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-pltcl", rpm:"postgresql84-pltcl~8.4.4~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-python", rpm:"postgresql84-python~8.4.4~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-server", rpm:"postgresql84-server~8.4.4~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-tcl", rpm:"postgresql84-tcl~8.4.4~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql84-test", rpm:"postgresql84-test~8.4.4~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
