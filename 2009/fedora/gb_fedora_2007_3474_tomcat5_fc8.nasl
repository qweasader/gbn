###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for tomcat5 FEDORA-2007-3474
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2007-November/msg00545.html");
  script_oid("1.3.6.1.4.1.25623.1.0.861582");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-02-27 16:23:18 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name:"FEDORA", value:"2007-3474");
  script_cve_id("CVE-2007-1355", "CVE-2007-3386", "CVE-2007-3385", "CVE-2007-3382", "CVE-2007-2450", "CVE-2007-2449", "CVE-2007-5461", "CVE-2007-1358");
  script_name("Fedora Update for tomcat5 FEDORA-2007-3474");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat5'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC8");
  script_tag(name:"affected", value:"tomcat5 on Fedora 8");
  script_tag(name:"solution", value:"Please install the updated package(s).");
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

if(release == "FC8")
{
  if ((res = isrpmvuln(pkg:"tomcat5", rpm:"tomcat5~5.5.25~1jpp.1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-jasper-eclipse", rpm:"tomcat5-jasper-eclipse~5.5.25~1jpp.1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-debuginfo", rpm:"tomcat5-debuginfo~5.5.25~1jpp.1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-webapps", rpm:"tomcat5-webapps~5.5.25~1jpp.1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-jasper", rpm:"tomcat5-jasper~5.5.25~1jpp.1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-jasper-javadoc", rpm:"tomcat5-jasper-javadoc~5.5.25~1jpp.1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api", rpm:"tomcat5-servlet-2.4-api~5.5.25~1jpp.1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-common-lib", rpm:"tomcat5-common-lib~5.5.25~1jpp.1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api-javadoc", rpm:"tomcat5-jsp-2.0-api-javadoc~5.5.25~1jpp.1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api-javadoc", rpm:"tomcat5-servlet-2.4-api-javadoc~5.5.25~1jpp.1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api", rpm:"tomcat5-jsp-2.0-api~5.5.25~1jpp.1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-server-lib", rpm:"tomcat5-server-lib~5.5.25~1jpp.1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-admin-webapps", rpm:"tomcat5-admin-webapps~5.5.25~1jpp.1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}