###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for apr CESA-2009:1204 centos5 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-August/016072.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880754");
  script_version("2022-05-31T15:38:36+0100");
  script_tag(name:"last_modification", value:"2022-05-31 15:38:36 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:1204");
  script_cve_id("CVE-2009-2412");
  script_name("CentOS Update for apr CESA-2009:1204 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apr'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"apr on CentOS 5");
  script_tag(name:"insight", value:"The Apache Portable Runtime (APR) is a portability library used by the
  Apache HTTP Server and other projects. It aims to provide a free library
  of C data structures and routines. apr-util is a utility library used with
  APR. This library provides additional utility interfaces for APR, including
  support for XML parsing, LDAP, database interfaces, URI parsing, and more.

  Multiple integer overflow flaws, leading to heap-based buffer overflows,
  were found in the way the Apache Portable Runtime (APR) manages memory pool
  and relocatable memory allocations. An attacker could use these flaws to
  issue a specially-crafted request for memory allocation, which would lead
  to a denial of service (application crash) or, potentially, execute
  arbitrary code with the privileges of an application using the APR
  libraries. (CVE-2009-2412)

  All apr and apr-util users should upgrade to these updated packages, which
  contain backported patches to correct these issues. Applications using the
  APR libraries, such as httpd, must be restarted for this update to take
  effect.");
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

  if ((res = isrpmvuln(pkg:"apr", rpm:"apr~1.2.7~11.el5_3.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apr-devel", rpm:"apr-devel~1.2.7~11.el5_3.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apr-docs", rpm:"apr-docs~1.2.7~11.el5_3.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apr-util", rpm:"apr-util~1.2.7~7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apr-util-devel", rpm:"apr-util-devel~1.2.7~7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apr-util-docs", rpm:"apr-util-docs~1.2.7~7.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
