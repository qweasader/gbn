###############################################################################
# OpenVAS Vulnerability Test
#
# Netgear GS110TP Default Password
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103666");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Netgear GS110TP Default Credentials (HTTP)");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2013-02-20 12:01:48 +0100 (Wed, 20 Feb 2013)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Web_Server/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"summary", value:"The remote Netgear GS110TP has the default password 'password'.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: Web Server" >!< banner)exit(0);

url = '/base/main_login.html';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("<TITLE>NetGear GS110TP</TITLE>" >!< buf)exit(0);

host = http_host_name(port:port);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Referer: http://", host, "/base/main_login.html\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 52\r\n",
             "\r\n",
             "pwd=password&login.x=0&login.y=0&err_flag=0&err_msg=");

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(result !~ "^HTTP/1\.[01] 200")exit(0);

cookie = eregmatch(pattern:string("Set-Cookie: ([^\r\n ]+)"), string:result);
if(isnull(cookie[1]))exit(0);

co = cookie[1];

url = '/base/system/management/sysInfo.html';

req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Cookie: ", co, "\r\n\r\n");

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("System Name" >< result && "Serial Number" >< result && "Base MAC Address" >< result) {

  security_message(port:port);
  exit(0);
}

exit(99);
