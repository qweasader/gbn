###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2016:2946 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882610");
  script_version("2021-10-14T11:01:30+0000");
  script_tag(name:"last_modification", value:"2021-10-14 11:01:30 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-12-17 05:30:47 +0100 (Sat, 17 Dec 2016)");
  script_cve_id("CVE-2016-9893", "CVE-2016-9895", "CVE-2016-9897", "CVE-2016-9898",
                "CVE-2016-9899", "CVE-2016-9900", "CVE-2016-9901", "CVE-2016-9902",
                "CVE-2016-9904", "CVE-2016-9905");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-03 17:19:00 +0000 (Fri, 03 Aug 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for firefox CESA-2016:2946 centos6");
  script_tag(name:"summary", value:"Check the version of firefox");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 45.6.0 ESR.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2016-9893, CVE-2016-9899, CVE-2016-9895, CVE-2016-9897,
CVE-2016-9898, CVE-2016-9900, CVE-2016-9901, CVE-2016-9902, CVE-2016-9904,
CVE-2016-9905)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Philipp, Wladimir Palant, Nils, Jann Horn, Aral,
Andrew Krasichkov, insertscript, Jan de Mooij, Iris Hsiao, Christian
Holler, Carsten Book, Timothy Nikkel, Christoph Diehl, Olli Pettay, Raymond
Forbes, and Boris Zbarsky as the original reporters.");
  script_tag(name:"affected", value:"firefox on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:2946");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-December/022178.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~45.6.0~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
