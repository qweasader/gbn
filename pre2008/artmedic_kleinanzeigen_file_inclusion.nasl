# OpenVAS Vulnerability Test
# Description: Artmedic Kleinanzeigen File Inclusion Vulnerability
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
#

# From: Francisco Alisson <dominusvis@click21.com.br>
# Subject: Artmedic kleinanzeigen include vulnerability
# Date: 19.7.2004 05:25

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13654");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0624");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10746");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Artmedic Kleinanzeigen File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"The file inclusion vulnerability allows a remote attacker to include
  external PHP files as if they were the server's own, this causing the product to execute arbitrary code");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Artmedic Kleinanzeigen, an email verifying PHP script,
  has been found to contain an external file inclusion vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/kleinanzeigen", "/php/kleinanzeigen", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  foreach file( make_list( "/index.php", "/index.php3", "/index.php4" ) ) {

    buf = http_get_cache( item:dir + file, port:port );
    if( ! buf || buf !~ "^HTTP/1\.[01] 200" || buf !~ "(Freewarescript by artmedic webdesign|Kleinanzeigen von artmedic webdesign|<title>Kleinanzeigen</title>)" )
      continue;

    url = string( dir, file, "?id=http://xx./" );
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );
    if( ! buf )
      continue;

    if( 'ReadFile("http://xx.")' >< buf ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 0 );
