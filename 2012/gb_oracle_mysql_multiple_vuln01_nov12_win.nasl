###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle MySQL Server Multiple Vulnerabilities-01 Nov12 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803111");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-3197", "CVE-2012-3163", "CVE-2012-3158", "CVE-2012-3150");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-11-26 16:54:56 +0530 (Mon, 26 Nov 2012)");
  script_name("Oracle MySQL Server Multiple Vulnerabilities-01 Nov12 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51008/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55990");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56017");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56036");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/51008");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html");
  script_xref(name:"URL", value:"https://support.oracle.com/rs?type=doc&id=1475188.1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to disclose potentially
  sensitive information, manipulate certain data and cause a DoS (Denial of Service).");

  script_tag(name:"affected", value:"Oracle MySQL version 5.1.x to 5.1.64 and
  Oracle MySQL version 5.5.x to 5.5.26 on Windows.");

  script_tag(name:"insight", value:"The flaws are due to multiple unspecified errors in MySQL server component
  related to server replication, information schema, protocol and server optimizer.");

  script_tag(name:"solution", value:"Apply the patch from the referenced vendor advisory or upgrade to the latest version.");

  script_tag(name:"summary", value:"Oracle MySQL server is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

vers = eregmatch(pattern:"([0-9.a-z]+)", string:vers);
if(vers[1])
{
  if(version_in_range(version:vers[1], test_version:"5.1.0", test_version2:"5.1.64") ||
     version_in_range(version:vers[1], test_version:"5.5.0", test_version2:"5.5.26")){
    report = report_fixed_ver(installed_version:vers[1], fixed_version:"Apply the patch");
    security_message(data:report, port:port);
    exit(0);
  }
  exit(99);
}

exit(0);