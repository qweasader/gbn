###############################################################################
# OpenVAS Vulnerability Test
#
# IBM HTTP Server Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801996");
  script_version("2022-02-17T14:14:34+0000");
  script_cve_id("CVE-2011-1360");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-11-08 19:48:57 +0530 (Tue, 08 Nov 2011)");
  script_name("IBM HTTP Server Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80, 8880, 8008);
  script_mandatory_keys("IBM_HTTP_Server/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"IBM HTTP Server version 2.0.47 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied input
  by a documentation page located in the 'manual/ibm' sub directories. That
  allows attackers to execute arbitrary HTML and script code in a user's
  browser session in the context of an affected site.");

  script_tag(name:"summary", value:"IBM HTTP Server is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"solution", value:"Update to version 2.0.48 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

ibmWebSer = http_get_remote_headers(port:port);

if("Server: IBM_HTTP_Server" >< ibmWebSer) {
  ver = eregmatch(pattern:"IBM_HTTP_Server/([0-9.]+)", string:ibmWebSer);
  if(ver[1]) {
    if(version_is_less_equal(version:ver[1], test_version:"2.0.47")) {
      report = report_fixed_ver(installed_version:ver[1], vulnerable_range:"Less than or equal to 2.0.47");
      security_message(port:port, data:report);
      exit(0);
    }
  }
}
