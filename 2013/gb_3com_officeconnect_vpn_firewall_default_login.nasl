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

CPE = "cpe:/o:hp:3com_officeconnect_gigabit_vpn_firewall_software";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103711");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2013-05-14 11:24:55 +0200 (Tue, 14 May 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("3Com OfficeConnect VPN Firewall Default Credentials (HTTP)");

  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_3com_officeconnect_vpn_firewall_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("3com_officeconnect_vpn_firewall/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"summary", value:"The remote 3Com OfficeConnect VPN Firewall is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to
  sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Tries to login as Admin with password 'admin'.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

req = string("POST /cgi-bin/admin?page=x HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
             "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
             "Accept-Encoding: Identity\r\n",
             "Connection: close\r\n",
             "Referer: http://", host, "/cgi-bin/admin?page=x\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 34\r\n",
             "\r\n",
             "AdminPassword=admin&next=10&page=x");
result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(result =~ "^HTTP/1\.[01] 200" && "INPUT type=hidden name=tk" >< result) {

  tk_val = eregmatch(pattern:'INPUT type=hidden name=tk value="([^"]+)"', string:result);
  if(isnull(tk_val[1]))
    exit(0);

  tk = tk_val[1];
  login_data = 'next=10&page=0&tk=' + tk;
  len = strlen(login_data);

  req = string("POST /cgi-bin/admin?page=x HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
               "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
               "Accept-Encoding: Identity\r\n",
               "Connection: close\r\n",
               "Referer: http://", host, "/cgi-bin/admin?page=x\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", len, "\r\n",
               "\r\n",
               login_data);
  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(result =~ "^HTTP/1\.[01] 200" && "/stbar.htm" >< result) {

    url = '/cgi-bin/admin?page=1&tk=' + tk + '&next=10';
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>administration menu" >< tolower(buf)) {
      report = "It was possible to login as Admin with password 'admin'.";
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
