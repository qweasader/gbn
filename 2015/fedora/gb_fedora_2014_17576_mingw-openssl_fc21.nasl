###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mingw-openssl FEDORA-2014-17576
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.868855");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2015-01-05 15:04:44 +0100 (Mon, 05 Jan 2015)");
  script_cve_id("CVE-2014-3566", "CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507",
                "CVE-2014-3511", "CVE-2014-3510", "CVE-2014-3508", "CVE-2014-3509",
                "CVE-2014-0221", "CVE-2014-0198", "CVE-2014-0224", "CVE-2014-0195",
                "CVE-2010-5298", "CVE-2014-3470");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Update for mingw-openssl FEDORA-2014-17576");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-openssl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"mingw-openssl on Fedora 21");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2014-17576");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-January/147353.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC21");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC21")
{

  if ((res = isrpmvuln(pkg:"mingw-openssl", rpm:"mingw-openssl~1.0.1j~1.fc21", rls:"FC21")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
