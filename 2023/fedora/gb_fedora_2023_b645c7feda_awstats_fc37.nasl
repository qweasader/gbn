# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.823141");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2022-46391");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-06 12:39:00 +0000 (Tue, 06 Dec 2022)");
  script_tag(name:"creation_date", value:"2023-01-18 02:03:45 +0000 (Wed, 18 Jan 2023)");
  script_name("Fedora: Security Advisory for awstats (FEDORA-2023-b645c7feda)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-b645c7feda");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GRFYH4DE3COMI3LJCOQQXA4FWOABU6Z2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'awstats'
  package(s) announced via the FEDORA-2023-b645c7feda advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Advanced Web Statistics is a powerful and full-featured tool that generates
advanced web server graphical statistics. This server log analyzer works
from the command line or as a CGI and shows all information your log contains,
in graphical web pages. It can analyze a lot of web/wap/proxy servers such as
Apache, IIS, Weblogic, Webstar, Squid, ... but also mail or FTP servers.

This program can measure visits, unique visitors, authenticated users, pages,
domains/countries, OS busiest times, robot visits, type of files, search
engines/keywords used, visit duration, HTTP errors and more...
Statistics can be updated from a browser or your scheduler.
The program also supports virtual servers, plugins and a lot of features.");

  script_tag(name:"affected", value:"'awstats' package(s) on Fedora 37.");

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

if(release == "FC37") {

  if(!isnull(res = isrpmvuln(pkg:"awstats", rpm:"awstats~7.8~9.fc37", rls:"FC37"))) {
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
