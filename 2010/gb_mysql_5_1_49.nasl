# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:mysql:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100785");
  script_version("2022-07-22T10:11:18+0000");
  script_tag(name:"last_modification", value:"2022-07-22 10:11:18 +0000 (Fri, 22 Jul 2022)");
  script_tag(name:"creation_date", value:"2010-09-07 15:26:31 +0200 (Tue, 07 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2010-3677");
  script_name("Oracle MySQL < 5.1.49 Multiple DoS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("mysql_version.nasl");
  script_mandatory_keys("MySQL/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42646");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42633");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42643");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42598");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42596");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42638");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42599");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42625");
  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=54575");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-49.html");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the database, denying
  access to legitimate users.");

  script_tag(name:"affected", value:"Oracle MySQL versions prior to 5.1.49.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

vers = eregmatch(pattern:"([0-9.a-z]+)", string:vers);
if(!vers || vers[1] !~ "^5\.")
  exit(99);

version = vers[1];

if(version_is_less(version:version, test_version:"5.1.49")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"5.1.49", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);