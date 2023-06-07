##############################################################################
# OpenVAS Vulnerability Test
#
# Arbor Networks Peakflow SP 'index/' Cross Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802958");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-4685");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-09-11 11:47:18 +0530 (Tue, 11 Sep 2012)");
  script_name("Arbor Networks Peakflow SP 'index/' Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48728");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52881");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74648");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-04/0019.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-04/0037.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-04/0036.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"Arbor Networks Peakflow SP 5.1.1 before patch 6, 5.5 before patch 4,
  and 5.6.0 before patch 1");

  script_tag(name:"insight", value:"Input appended to the URL after 'index/' in the login interface is not
  properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to Arbor Networks Peakflow SP 5.1.1 patch 6,
  5.5 patch 4, 5.6.0 patch 1 or later.");

  script_tag(name:"summary", value:"Arbor Networks Peakflow SP is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:443);

url = "/index";
req = http_get(item:url, port:port);

res = http_keepalive_send_recv(port:port, data:req);

if(res && ">Welcome to Arbor Networks Peakflow SP<" >< res)
{
  url = url + '/"><script>alert(document.cookie)</script>';
  req2 = http_get(item:url, port:port);

  res2 = http_keepalive_send_recv(port:port, data:req2);

  if(res2 && "<script>alert(document.cookie)</script>" >< res2 &&
     res2 =~ "HTTP/1.. 200" &&
     ">Welcome to Arbor Networks Peakflow SP<" >< res2){
    security_message(port:port);
    exit(0);
  }
}

exit(99);
