###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_1199_patch_centos6.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for patch CESA-2018:1199 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882870");
  script_version("2021-05-26T06:00:13+0200");
  script_tag(name:"last_modification", value:"2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2018-05-03 05:29:33 +0200 (Thu, 03 May 2018)");
  script_cve_id("CVE-2018-1000156");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-30 10:15:00 +0000 (Tue, 30 Jul 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for patch CESA-2018:1199 centos6");
  script_tag(name:"summary", value:"Check the version of patch");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The patch program applies diff files to
  originals. The diff command is used to compare an original to a changed file.
  Diff lists the changes made to the file. A person who has the original file
  can then use the patch command with the diff file to add the changes to their
  original file (patching the file).

Patch should be installed because it is a common way of upgrading
applications.

Security Fix(es):

  * patch: Malicious patch files cause ed to execute arbitrary commands
(CVE-2018-1000156)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.");
  script_tag(name:"affected", value:"patch on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:1199");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-May/022819.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"patch", rpm:"patch~2.6~8.el6_9", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
