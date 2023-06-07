###############################################################################
# OpenVAS Vulnerability Test
#
# Netmechanica NetDecision Dashboard Server Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802703");
  script_version("2022-02-15T13:40:32+0000");
  script_cve_id("CVE-2012-1464");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-02-15 13:40:32 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2012-03-08 17:47:52 +0530 (Thu, 08 Mar 2012)");
  script_name("Netmechanica NetDecision Dashboard Server Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=478");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18543/");
  script_xref(name:"URL", value:"http://secpod.org/exploits/SecPod_Netmechanica_NetDecision_Dashboard_Server_Info_Disc_PoC.py");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_Netmechanica_NetDecision_Dashboard_Server_Info_Disc_Vuln.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8090);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain sensitive information.");

  script_tag(name:"affected", value:"NetDecision Dashboard Server version 4.5.1.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of malicious HTTP request
  appended with '?' character, which discloses the Dashboard server's web script physical path.");

  script_tag(name:"solution", value:"Upgrade to NetDecision Dashboard Server 4.6.1 or later.");

  script_tag(name:"summary", value:"NetDecision Dashboard Server is prone to an information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8090);

rcvRes = http_get_cache(item:"/", port:port);

if(!rcvRes || ("Server: NetDecision-HTTP-Server" >!< rcvRes &&
   !egrep(pattern:">Copyright .*NetMechanica", string:rcvRes))){
  exit(0);
}

sndReq1 = http_get(item:"/?", port:port);
rcvRes1 = http_keepalive_send_recv(port:port, data:sndReq1);
if(!rcvRes1){
  exit(0);
}

if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes1) &&
   egrep(pattern:"Failed to open script file: .?:\\.*NetDecision\\" +
            "Script Folders\\DashboardServer", string:rcvRes1)){
  security_message(port:port);
  exit(0);
}

exit(99);
