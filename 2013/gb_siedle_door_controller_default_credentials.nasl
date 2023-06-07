# Copyright (C) 2013 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103820");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Siedle Door Controller Default Credentials (HTTP)");

  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2013-10-24 10:01:48 +0100 (Thu, 24 Oct 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Z-World_Rabbit/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"impact", value:"The 'Service' account has a default password of 'Siedle' which gives almost
  full access to the system like adding, renaming, or deleting doors and users, and force all the doors open.");

  script_tag(name:"vuldetect", value:"This check tries to login into the remote Siedle Door Controller.");

  script_tag(name:"insight", value:"It was possible to login with username 'Service' and password 'Siedle'.");

  script_tag(name:"solution", value:"Change the password or contact your vendor for an update.");

  script_tag(name:"summary", value:"The remote Siedle Door Controller is using known default credentials.");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port:port);
if("Server: Z-World Rabbit" >!< banner)exit(0);

url = "/login.zht";
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("Siedle" >!< buf)exit(0);

host = http_host_name(port:port);

req = 'POST /login.cgi HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Referer: http://' + host + '/login.zht\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: 125\r\n' +
      '\r\n' +
      'm_webdata.m_cgiLogin.m_user=Service&m_webdata.m_cgiLogin.m_passwd=Siedle&m_webdata.m_cgiLogin.m_lang=en&action.x=0&action.y=0';

buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
if("Set-Cookie" >!< buf)exit(0);

cookie = eregmatch(pattern:'Set-Cookie: ([^\r\n]+)', string:buf);
if(isnull(cookie[1]))exit(0);
co = cookie[1];

req = 'GET /cfg/usrlist.zht HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Cookie: ' + co + '\r\n\r\n';

buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf =~ "^HTTP/1\.[01] 200" && "usrlist.name" >< buf) {
  security_message(port:port);
  exit(0);
}

exit(99);
