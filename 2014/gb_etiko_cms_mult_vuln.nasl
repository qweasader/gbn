###############################################################################
# OpenVAS Vulnerability Test
#
# Etiko CMS Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804882");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-8506", "CVE-2014-8505");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-11-13 12:51:58 +0530 (Thu, 13 Nov 2014)");
  script_name("Etiko CMS Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Etiko CMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Input passed via the 'page_id' GET parameter
  to /loja/index.php script and 'article_id' parameter to /index.php script is not
  validated before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database allowing
  for the manipulation or disclosure of arbitrary data, and execute arbitrary HTML
  and script code in a users browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Etiko CMS version 2.14 and earlier.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128644");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70796");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70797");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

http_port = http_get_port(default:80);

if(!http_can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/etiko", "/cms", http_cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if(rcvRes && ">Etiko<" >< rcvRes && "etikweb.com" >< rcvRes)
  {
    url = dir + '/index.php?page_id=19"><script>alert(document.cookie)</script>';

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"><script>alert\(document\.cookie\)</script>",
       extra_check:">Etiko<"))
    {
      report = http_report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
