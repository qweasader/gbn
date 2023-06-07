###############################################################################
# OpenVAS Vulnerability Test
#
# phpwind Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805192");
  script_version("2021-10-21T13:57:32+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-21 13:57:32 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2015-05-28 14:35:27 +0530 (Thu, 28 May 2015)");

  script_tag(name:"qod_type", value:"remote_vul");
  script_name("phpwind Multiple Vulnerabilities");

  script_tag(name:"summary", value:"phpwind is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to insufficient sanitization
  of user-supplied data to '/goto.php' script via 'url' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to redirect to any server or create a specially crafted request that
  would execute arbitrary script code in a user's browser session within the
  trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"phpwind version 8.7 and prior.");

  script_tag(name:"solution", value:"Update to version 9.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/May/106");
  script_xref(name:"URL", value:"http://diebiyi.com/articles/security/phpwind-v8-7-xss");
  script_xref(name:"URL", value:"http://securityrelated.blogspot.in/2015/05/phpwind-v87-xss.html");
  script_xref(name:"URL", value:"https://itswift.wordpress.com/2015/05/24/phpwind-v8-7-xss");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.phpwind.net");
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

foreach dir (make_list_unique("/",  "/phpwind", "/cms", http_cgi_dirs( port:http_port))) {

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:dir + "/index.php",  port:http_port);

  if("Powered by phpwind" >< rcvRes)
  {
    url = dir + '/goto.php?url="><script>alert(document.cookie)</script>';

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"><script>alert\(document\.cookie\)</script>"))
    {
      report = http_report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
