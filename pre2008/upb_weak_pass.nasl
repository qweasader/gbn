###############################################################################
# OpenVAS Vulnerability Test
#
# Ultimate PHP Board users.dat Information Disclosure
#
# Authors:
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
# Fixes by Tenable:
#   - removed '/upb' from first request string so test is not dependent
#     on a specific installation directory.
#   - actually tested for users.dat content rather than the response code.
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
  script_oid("1.3.6.1.4.1.25623.1.0.19497");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2005", "CVE-2005-2030");
  script_xref(name:"OSVDB", value:"17374");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Ultimate PHP Board 'users.dat' Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/402506");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13975");
  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/402461");

  script_tag(name:"summary", value:"Ultimate PHP Board (UPB) is prone to an information disclosure
  vulnerability");

  script_tag(name:"insight", value:"The remote version of this software is prone to a weak password
  encryption vulnerability and may store the users.dat file under the web document root with
  insufficient access control.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/db/users.dat";

  # nb: records look like:
  #     user_name<~>password<~>level<~>email<~>view_email<~>mail_list<~>location<~>url<~>avatar<~>icq<~>aim<~>msn<~>sig<~>posts<~>date_added<~>id
  if( http_vuln_check( port:port, url:url, pattern:"<~>20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]<~>[0-9]+$" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }

  # See if the version is known to be vulnerable.
  res = http_get_cache( item:dir + "/index.php", port:port );

  if( ver = egrep( pattern:"Powered by UPB Version : 1\.([0-8]|9\.[0-6])", string:res ) ) {
    report = report_fixed_ver( installed_version:ver, fixed_version:"None" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
