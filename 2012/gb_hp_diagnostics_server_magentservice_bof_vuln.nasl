###############################################################################
# OpenVAS Vulnerability Test
#
# HP Diagnostics Server 'magentservice.exe' Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:hp:diagnostics_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802386");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2011-4789");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-02-01 14:14:14 +0530 (Wed, 01 Feb 2012)");
  script_name("HP Diagnostics Server 'magentservice.exe' Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47574/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51398");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Jan/88");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-016/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_hp_diagnostics_server_detect.nasl");
  script_mandatory_keys("hp/diagnostics_server/detected");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code within the context of the application or cause a denial of service condition.");

  script_tag(name:"affected", value:"HP Diagnostics Server 9.00.");

  script_tag(name:"insight", value:"The flaw is due to an error within the magentservice.exe process
  when processing a specially crafted request sent to TCP port 23472 and causing
  a stack-based buffer overflow.");

  script_tag(name:"summary", value:"HP Diagnostics Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version:vers, test_version:"9.00")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Equal to 9.00", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
