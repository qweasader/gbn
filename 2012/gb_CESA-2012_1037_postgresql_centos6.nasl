###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for postgresql CESA-2012:1037 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881062");
  script_version("2022-05-31T15:35:19+0100");
  script_tag(name:"last_modification", value:"2022-05-31 15:35:19 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2012-07-30 15:59:20 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-2143", "CVE-2012-2655");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name:"CESA", value:"2012:1037");
  script_name("CentOS Update for postgresql CESA-2012:1037 centos6");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018728.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/8.4/static/release.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"postgresql on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"PostgreSQL is an advanced object-relational database management system
  (DBMS).

  A flaw was found in the way the crypt() password hashing function from the
  optional PostgreSQL pgcrypto contrib module performed password
  transformation when used with the DES algorithm. If the password string to
  be hashed contained the 0x80 byte value, the remainder of the string was
  ignored when calculating the hash, significantly reducing the password
  strength. This made brute-force guessing more efficient as the whole
  password was not required to gain access to protected resources.
  (CVE-2012-2143)

  Note: With this update, the rest of the string is properly included in the
  DES hash. Therefore, any previously stored password values that are
  affected by this issue will no longer match. In such cases, it will be
  necessary for those stored password hashes to be updated.

  A denial of service flaw was found in the way the PostgreSQL server
  performed a user privileges check when applying SECURITY DEFINER or SET
  attributes to a procedural language's (such as PL/Perl or PL/Python) call
  handler function. A non-superuser database owner could use this flaw to
  cause the PostgreSQL server to crash due to infinite recursion.
  (CVE-2012-2655)

  Upstream acknowledges Rubin Xu and Joseph Bonneau as the original reporters
  of the CVE-2012-2143 issue.

  These updated packages upgrade PostgreSQL to version 8.4.12, which fixes
  these issues as well as several non-security issues. Refer to the
  linked PostgreSQL Release Notes for a full list of changes.

  All PostgreSQL users are advised to upgrade to these updated packages,
  which correct these issues. If the postgresql service is running, it will
  be automatically restarted after installing this update.");
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

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.4.12~1.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~8.4.12~1.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~8.4.12~1.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~8.4.12~1.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~8.4.12~1.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~8.4.12~1.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~8.4.12~1.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~8.4.12~1.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~8.4.12~1.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~8.4.12~1.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
