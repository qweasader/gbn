###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_1836_plexus-archiver_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for plexus-archiver CESA-2018:1836 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882911");
  script_version("2021-05-25T06:00:12+0200");
  script_tag(name:"last_modification", value:"2021-05-25 06:00:12 +0200 (Tue, 25 May 2021)");
  script_tag(name:"creation_date", value:"2018-06-15 05:47:33 +0200 (Fri, 15 Jun 2018)");
  script_cve_id("CVE-2018-1002200");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:32:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for plexus-archiver CESA-2018:1836 centos7");
  script_tag(name:"summary", value:"Check the version of plexus-archiver");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Plexus project provides a full software
  stack for creating and executing software projects. Based on the Plexus
  container, the applications can utilise component-oriented programming to build
  modular, reusable components that can easily be assembled and reused. The
  plexus-archiver component provides functions to create and extract archives.

Security Fix(es):

  * plexus-archiver: arbitrary file write vulnerability / arbitrary code
execution using a specially crafted zip file (CVE-2018-1002200)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Danny Grander (Snyk) for reporting this issue.");
  script_tag(name:"affected", value:"plexus-archiver on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:1836");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-June/022922.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"plexus-archiver", rpm:"plexus-archiver~2.4.2~5.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"plexus-archiver-javadoc", rpm:"plexus-archiver-javadoc~2.4.2~5.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
