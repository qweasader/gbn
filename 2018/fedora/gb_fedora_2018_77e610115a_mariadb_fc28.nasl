###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mariadb FEDORA-2018-77e610115a
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
  script_oid("1.3.6.1.4.1.25623.1.0.875017");
  script_version("2022-07-21T10:11:30+0000");
  script_tag(name:"last_modification", value:"2022-07-21 10:11:30 +0000 (Thu, 21 Jul 2022)");
  script_tag(name:"creation_date", value:"2018-09-01 07:34:32 +0200 (Sat, 01 Sep 2018)");
  script_cve_id("CVE-2018-3060", "CVE-2018-3064", "CVE-2018-3063", "CVE-2018-3058",
                "CVE-2018-3066", "CVE-2018-3081", "CVE-2018-2767", "CVE-2018-2755",
                "CVE-2018-2761", "CVE-2018-2766", "CVE-2018-2771", "CVE-2018-2781",
                "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2787", "CVE-2018-2813",
                "CVE-2018-2817", "CVE-2018-2819", "CVE-2018-2786", "CVE-2018-2759",
                "CVE-2018-2777", "CVE-2018-2810");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-19 16:40:00 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mariadb FEDORA-2018-77e610115a");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"affected", value:"mariadb on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-77e610115a");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OQGHKAL7T56PH5I3O7WENFVBDAK3OF75");
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

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.2.17~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}