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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902952");
  script_version("2022-04-25T14:50:49+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-02-26 11:48:51 +0530 (Tue, 26 Feb 2013)");
  script_name("AbanteCart Multiple Cross-Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52165");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57948");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/82073");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013020095");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120273");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52165");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5125.php");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"AbanteCart version 1.1.3 and prior");

  script_tag(name:"insight", value:"Input passed via the 'limit', 'page', 'rt', 'sort', 'currency',
  'product_id', 'language', 's', 'manufacturer_id', and 'token' GET parameters
  to index.php is not properly sanitized before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to version 1.1.4 or later.");

  script_tag(name:"summary", value:"AbanteCart is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.abantecart.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/", "/abantecart", "/cart", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( ! res ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && ">AbanteCart<" >< res &&
      '>Powered by Abantecart' >< res && '>Cart<' >< res ) {

    url = dir + '/index.php?limit="><script>alert(document.cookie);</script>';

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"><script>alert\(document\.cookie\);</script>",
       extra_check:">AbanteCart<"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
