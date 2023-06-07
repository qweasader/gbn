###############################################################################
# OpenVAS Vulnerability Test
#
# Tribiq CMS Direct Request Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.805232");
  script_version("2021-10-28T14:26:49+0000");
  script_cve_id("CVE-2011-2727");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-28 14:26:49 +0000 (Thu, 28 Oct 2021)");
  script_tag(name:"creation_date", value:"2014-12-31 15:18:53 +0530 (Wed, 31 Dec 2014)");
  script_name("Tribiq CMS Direct Request Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"Tribiq CMS is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is possible to read full path to installation directory");

  script_tag(name:"insight", value:"The error exists as application reveals
  the full path to installation directory in an error message.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain knowledge of the web root directory and other potentially
  sensitive information.");

  script_tag(name:"affected", value:"Tribiq CMS version 5.2.7b and probably
  prior.");

  script_tag(name:"solution", value:"Upgrade to Tribiq CMS version 5.2.7c or
  later.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB22857");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/tribiq");
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

foreach dir (make_list_unique("/", "/community", "/tribiqcms", "/cms", http_cgi_dirs(port:cmsPort)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/admin/welcome.php"),  port:cmsPort);
  rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);

  if (rcvRes && rcvRes =~ ">Welcome to Tribiq CMS<")
  {
    url = dir + "/cmsjs/plugin.js.php";

    sndReq = http_get(item:url,  port:cmsPort);
    rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);

    if(rcvRes && rcvRes =~ ">Warning<.*Invalid argument.*in <b")
    {
      security_message(port:cmsPort);
      exit(0);
    }
  }
}

exit(99);
