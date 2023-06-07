###############################################################################
# OpenVAS Vulnerability Test
#
# Movable Type SQL Injection Vulnerability
#
# Authors:
# Deependra Bapna <bdeepednra@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:sixapart:movable_type";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805390");
  script_version("2021-10-21T13:57:32+0000");
  script_cve_id("CVE-2014-9057");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-21 13:57:32 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2015-05-27 17:12:55 +0530 (Wed, 27 May 2015)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Movable Type SQL Injection Vulnerability");

  script_tag(name:"summary", value:"movable type is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to the XML-RPC interface
  not properly sanitizing user-supplied input to unspecified vectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Movable Type 5.2.x before 5.2.11");

  script_tag(name:"solution", value:"Upgrade to Movable Type 5.2.11.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://movabletype.org/documentation/appendices/release-notes/6.0.6.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mt_detect.nasl");
  script_mandatory_keys("movabletype/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!http_port = get_app_port(cpe:CPE))
  exit(0);

if(!movVer = get_app_version(cpe:CPE, port:http_port))
  exit(0);

if(version_in_range(version:movVer, test_version:"5.2.0", test_version2:"5.2.10")) {
  report = report_fixed_ver(installed_version: movVer, fixed_version: "5.2.10");
  security_message(data:report, port:http_port);
  exit(0);
}

exit(99);
