# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.880593");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2010:0742");
  script_cve_id("CVE-2010-3433");
  script_name("CentOS Update for postgresql CESA-2010:0742 centos5 i386");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-October/017069.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/7.4/static/release.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/8.1/static/release.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/8.4/static/release.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"postgresql on CentOS 5");
  script_tag(name:"insight", value:"PostgreSQL is an advanced object-relational database management system
  (DBMS). PL/Perl and PL/Tcl allow users to write PostgreSQL functions in the
  Perl and Tcl languages. The PostgreSQL SECURITY DEFINER parameter, which
  can be used when creating a new PostgreSQL function, specifies that the
  function will be executed with the privileges of the user that created it.

  It was discovered that a user could utilize the features of the PL/Perl and
  PL/Tcl languages to modify the behavior of a SECURITY DEFINER function
  created by a different user. If the PL/Perl or PL/Tcl language was used to
  implement a SECURITY DEFINER function, an authenticated database user could
  use a PL/Perl or PL/Tcl script to modify the behavior of that function
  during subsequent calls in the same session. This would result in the
  modified or injected code also being executed with the privileges of the
  user who created the SECURITY DEFINER function, possibly leading to
  privilege escalation. (CVE-2010-3433)

  For Red Hat Enterprise Linux 4, the updated postgresql packages upgrade
  PostgreSQL to version 7.4.30. Refer to the linked PostgreSQL Release Notes for a
  list of changes.

  For Red Hat Enterprise Linux 5, the updated postgresql packages upgrade
  PostgreSQL to version 8.1.22, and the updated postgresql84 packages upgrade
  PostgreSQL to version 8.4.5. Refer to the linked PostgreSQL Release Notes for a
  list of changes.

  All PostgreSQL users are advised to upgrade to these updated packages,
  which correct this issue. If the postgresql service is running, it will be
  automatically restarted after installing this update.");
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

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.1.22~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~8.1.22~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~8.1.22~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~8.1.22~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~8.1.22~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-pl", rpm:"postgresql-pl~8.1.22~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-python", rpm:"postgresql-python~8.1.22~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~8.1.22~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-tcl", rpm:"postgresql-tcl~8.1.22~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~8.1.22~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
