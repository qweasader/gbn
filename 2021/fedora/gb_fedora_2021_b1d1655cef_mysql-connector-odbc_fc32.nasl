# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.878942");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2021-1998", "CVE-2021-2001", "CVE-2021-2002", "CVE-2021-2006", "CVE-2021-2007", "CVE-2021-2009", "CVE-2021-2010", "CVE-2021-2011", "CVE-2021-2012", "CVE-2021-2016", "CVE-2021-2019", "CVE-2021-2020", "CVE-2021-2021", "CVE-2021-2022");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-22 09:15:00 +0000 (Tue, 22 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-02-15 04:03:23 +0000 (Mon, 15 Feb 2021)");
  script_name("Fedora: Security Advisory for mysql-connector-odbc (FEDORA-2021-b1d1655cef)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-b1d1655cef");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CS5THZSGI7O2CZO44NWYE57AG2T7NK3K");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-connector-odbc'
  package(s) announced via the FEDORA-2021-b1d1655cef advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An ODBC (rev 3) driver for MySQL, for use with unixODBC.");

  script_tag(name:"affected", value:"'mysql-connector-odbc' package(s) on Fedora 32.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC32") {

  if(!isnull(res = isrpmvuln(pkg:"mysql-connector-odbc", rpm:"mysql-connector-odbc~8.0.23~1.fc32", rls:"FC32"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);