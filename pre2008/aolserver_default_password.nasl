# OpenVAS Vulnerability Test
# Description: AOLserver Default Password
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10753");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("AOLserver Default Password (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 SecuriTeam");
  script_family("Default Accounts");
  script_dependencies("gb_aol_server_detect.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("aol/server/detected");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Change the default username and password on your web server.");

  script_tag(name:"summary", value:"The remote web server is running AOL web server (AOLserver) with
  the default username and password set.");

  script_tag(name:"impact", value:"An attacker may use this to gain control of the remote web server.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

CPE = "cpe:/a:aol:aolserver";

include("host_details.inc");
include("http_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = "/nstelemetry.adp";
req = string("GET ", url, " HTTP/1.0\r\nAuthorization: Basic bnNhZG1pbjp4\r\n\r\n");
res = http_send_recv(port:port, data:req);

if(ereg(string:res, pattern:"^HTTP/1\.[01] 200") && "AOLserver Telemetry" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
