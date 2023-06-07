###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for libldb FEDORA-2018-bc22d6c7bc
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
  script_oid("1.3.6.1.4.1.25623.1.0.874977");
  script_version("2021-06-09T02:00:19+0000");
  script_tag(name:"last_modification", value:"2021-06-09 02:00:19 +0000 (Wed, 09 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-08-21 06:56:45 +0200 (Tue, 21 Aug 2018)");
  script_cve_id("CVE-2018-1139", "CVE-2018-1140", "CVE-2018-10858", "CVE-2018-10918",
                "CVE-2018-10919");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-26 08:15:00 +0000 (Wed, 26 Jun 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for libldb FEDORA-2018-bc22d6c7bc");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libldb'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"affected", value:"libldb on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-bc22d6c7bc");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UMELAF56SFMIHXRXGSB7LFC6JJDUHRUA");
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

  if ((res = isrpmvuln(pkg:"libldb", rpm:"libldb~1.4.0~3.fc28.1.3.5", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
