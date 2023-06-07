###############################################################################
# OpenVAS Vulnerability Test
#
# Your Online Shop 'products_id' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805000");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-6618");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-10-16 16:50:50 +0530 (Thu, 16 Oct 2014)");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Your Online Shop 'products_id' Parameter Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Your Online Shop is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"This flaw exists due to an insufficient sanitization
  of input to the 'products_id' parameter before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"Your Online Shop version 1.1.8.6.1, Other
  versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/96163");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70073");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128336");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

serPort = http_get_port(default:80);

if(!http_can_host_php(port:serPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/youronlineshop", "/cart", "/shop", http_cgi_dirs(port:serPort)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir, "/index.php"), port:serPort);

  if("www.tecnibur.com/youronlineshop/" >< res && ">Your online shop<" >< res)
  {
    url = dir + '/?seccion=ver_prod&products_id=test"/><script>alert(document.cookie)</script><';

    if(http_vuln_check(port:serPort, url:url, check_header:TRUE,
       pattern:"><script>alert\(document.cookie\)</script><",
                extra_check: "nameLargeProdtest"))
    {
      security_message(port:serPort);
      exit(0);
    }
  }
}

exit(99);
