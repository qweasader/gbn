# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:invision_power_services:invision_power_board";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900981");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3974");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Invision Power Board Multiple SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/387879.php");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2413");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("invision_power_board/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to access and modify the backend
  database by injecting arbitrary SQL queries.");

  script_tag(name:"affected", value:"Invision Power Board version 3.0.0, 3.0.1, and 3.0.2.");

  script_tag(name:"insight", value:"The input passed into 'search_term' parameter in search.php and in 'aid'
  parameter in lostpass.php is not porpperly sanitisied before being used to construct SQL queries.");

  script_tag(name:"summary", value:"Invision Power Board is prone to multiple SQL Injection vulnerabilities.");

  script_tag(name:"solution", value:"Apply the referenced patch.");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!ipbPort = get_app_port(cpe:CPE))
  exit(0);

if (!ipbVer = get_app_version(cpe:CPE, port:ipbPort))
  exit(0);

if (ipbVer =~ "^3\.0\.(0|1|2)") {
  report = report_fixed_ver(installed_version:ipbVer, fixed_version:"See references");
  security_message(port:ipbPort, data:report);
  exit(0);
}

exit(99);