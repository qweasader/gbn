###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for httpd CESA-2013:1156 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881782");
  script_version("2022-05-31T14:55:16+0100");
  script_tag(name:"last_modification", value:"2022-05-31 14:55:16 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2013-08-16 09:00:54 +0530 (Fri, 16 Aug 2013)");
  script_cve_id("CVE-2013-1896");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for httpd CESA-2013:1156 centos5");

  script_tag(name:"affected", value:"httpd on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The Apache HTTP Server is a popular web server.

A flaw was found in the way the mod_dav module of the Apache HTTP Server
handled merge requests. An attacker could use this flaw to send a crafted
merge request that contains URIs that are not configured for DAV, causing
the httpd child process to crash. (CVE-2013-1896)

All httpd users should upgrade to these updated packages, which contain a
backported patch to correct this issue. After installing the updated
packages, the httpd daemon will be restarted automatically.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1156");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-August/019903.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
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

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.3~82.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.3~82.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.3~82.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.3~82.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
