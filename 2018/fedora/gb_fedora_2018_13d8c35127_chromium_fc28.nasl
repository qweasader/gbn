###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for chromium FEDORA-2018-13d8c35127
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
  script_oid("1.3.6.1.4.1.25623.1.0.875090");
  script_version("2021-06-11T11:00:20+0000");
  script_tag(name:"last_modification", value:"2021-06-11 11:00:20 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-09-22 08:14:48 +0200 (Sat, 22 Sep 2018)");
  script_cve_id("CVE-2018-16087", "CVE-2018-16088", "CVE-2018-16086", "CVE-2018-16065",
                "CVE-2018-16066", "CVE-2018-16067", "CVE-2018-16068", "CVE-2018-16069",
                "CVE-2018-16070", "CVE-2018-16071", "CVE-2018-16072", "CVE-2018-16073",
                "CVE-2018-16074", "CVE-2018-16075", "CVE-2018-16076", "CVE-2018-16077",
                "CVE-2018-16078", "CVE-2018-16085", "CVE-2018-16084", "CVE-2018-16083",
                "CVE-2018-16082", "CVE-2018-16081", "CVE-2018-16080", "CVE-2018-16079");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-16 14:00:00 +0000 (Wed, 16 Jan 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for chromium FEDORA-2018-13d8c35127");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"affected", value:"chromium on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-13d8c35127");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/W7HTLQRJ655AZ5TRDNCFDLBQ7BIAMB24");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC28");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~69.0.3497.92~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
