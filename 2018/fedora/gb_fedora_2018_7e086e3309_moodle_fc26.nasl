###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for moodle FEDORA-2018-7e086e3309
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
  script_oid("1.3.6.1.4.1.25623.1.0.874082");
  script_version("2021-06-10T11:00:22+0000");
  script_tag(name:"last_modification", value:"2021-06-10 11:00:22 +0000 (Thu, 10 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-01 07:56:20 +0100 (Thu, 01 Feb 2018)");
  script_cve_id("CVE-2018-1042", "CVE-2018-1043", "CVE-2018-1044", "CVE-2018-1045");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-27 19:15:00 +0000 (Sat, 27 Jul 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for moodle FEDORA-2018-7e086e3309");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"moodle on Fedora 26");
  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"FEDORA", value:"2018-7e086e3309");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MIKMPOO5ZH7DTJPQW43SQI3P33VNC6AN");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC26");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"moodle", rpm:"moodle~3.2.7~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
