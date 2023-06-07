###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mingw-libtasn1 FEDORA-2018-f8c54aeec4
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
  script_oid("1.3.6.1.4.1.25623.1.0.874061");
  script_version("2021-06-11T02:00:27+0000");
  script_tag(name:"last_modification", value:"2021-06-11 02:00:27 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-01-29 07:50:40 +0100 (Mon, 29 Jan 2018)");
  script_cve_id("CVE-2018-6003");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-22 19:20:00 +0000 (Thu, 22 Oct 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mingw-libtasn1 FEDORA-2018-f8c54aeec4");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-libtasn1'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"mingw-libtasn1 on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"FEDORA", value:"2018-f8c54aeec4");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YUIZJK4F3GBWYJSBQGHN5J7IVDVPCLM4");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC27");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"mingw32-libtasn1", rpm:"mingw32-libtasn1~4.13~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"mingw64-libtasn1", rpm:"mingw64-libtasn1~4.13~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
