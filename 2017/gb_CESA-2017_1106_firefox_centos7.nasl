###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2017:1106 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882699");
  script_version("2021-09-10T09:01:40+0000");
  script_tag(name:"last_modification", value:"2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-04-21 06:40:44 +0200 (Fri, 21 Apr 2017)");
  script_cve_id("CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5432", "CVE-2017-5433",
                "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5437",
                "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441",
                "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445",
                "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449",
                "CVE-2017-5451", "CVE-2017-5454", "CVE-2017-5455", "CVE-2017-5456",
                "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5464", "CVE-2017-5465",
                "CVE-2017-5466", "CVE-2017-5467", "CVE-2017-5469");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-07 17:53:00 +0000 (Tue, 07 Aug 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for firefox CESA-2017:1106 centos7");
  script_tag(name:"summary", value:"Check the version of firefox");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 52.1.0 ESR.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2017-5429, CVE-2017-5430, CVE-2017-5432, CVE-2017-5433,
CVE-2017-5434, CVE-2017-5435, CVE-2017-5436, CVE-2017-5437, CVE-2017-5438,
CVE-2017-5439, CVE-2017-5440, CVE-2017-5441, CVE-2017-5442, CVE-2017-5443,
CVE-2017-5444, CVE-2017-5445, CVE-2017-5446, CVE-2017-5447, CVE-2017-5448,
CVE-2017-5449, CVE-2017-5451, CVE-2017-5454, CVE-2017-5455, CVE-2017-5456,
CVE-2017-5459, CVE-2017-5460, CVE-2017-5464, CVE-2017-5465, CVE-2017-5466,
CVE-2017-5467, CVE-2017-5469)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Mozilla developers and community, Nils, Holger
Fuhrmannek, Atte Kettunen, Takeshi Terada, Huzaifa Sidhpurwala, Nicolas
Gregoire, Chamal De Silva, Chun Han Hsiao, Ivan Fratric of Google Project
Zero, Anonymous working with Trend Micro's Zero Day Initiative, Haik
Aftandilian, Paul Theriault, Julian Hector, Petr Cerny, Jordi Chancel, and
Heather Miller of Google Skia team as the original reporters.");
  script_tag(name:"affected", value:"firefox on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:1106");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-April/022398.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~52.1.0~2.el7.centos", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
