###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for apr CESA-2017:3270 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882807");
  script_version("2022-04-20T06:12:09+0000");
  script_tag(name:"last_modification", value:"2022-04-20 06:12:09 +0000 (Wed, 20 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-12-04 18:48:03 +0530 (Mon, 04 Dec 2017)");
  script_cve_id("CVE-2017-12613");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 18:16:00 +0000 (Mon, 18 Apr 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for apr CESA-2017:3270 centos6");
  script_tag(name:"summary", value:"Check the version of apr");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Apache Portable Runtime (APR) is a
portability library used by the Apache HTTP Server and other projects.
It provides a free library of C data structures and routines.

Security Fix(es):

  * An out-of-bounds array dereference was found in apr_time_exp_get(). An
attacker could abuse an unvalidated usage of this function to cause a
denial of service or potentially lead to data leak. (CVE-2017-12613)");
  script_tag(name:"affected", value:"apr on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:3270");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-November/022645.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"apr", rpm:"apr~1.3.9~5.el6_9.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apr-devel", rpm:"apr-devel~1.3.9~5.el6_9.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
