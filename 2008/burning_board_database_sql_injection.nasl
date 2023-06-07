###############################################################################
# OpenVAS Vulnerability Test
#
# Woltlab Burning Board SQL injection flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2008 David Maciejak
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

# ref: admin@batznet.com and Mustafa Can Bjorn

CPE = "cpe:/a:woltlab:burning_board";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80050");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_cve_id("CVE-2005-3369", "CVE-2006-1094");
  script_xref(name:"OSVDB", value:"20330");
  script_xref(name:"OSVDB", value:"23596");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Woltlab Burning Board SQL injection flaw");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2008 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("secpod_woltlab_burning_board_detect.nasl");
  script_mandatory_keys("WoltLabBurningBoard/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/426583/30/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15214");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16914");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"summary", value:"The remote web server contains a PHP script that is susceptible to SQL
  injection attacks.

  Description:

  The remote version of Burning Board includes an optional module, the Database module, that fails to properly
  sanitize the 'fileid' parameter of the 'info_db.php' script, which can be exploited to launch SQL injection
  attacks against the affected host.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/info_db.php?action=file&fileid=1/**/UNION/**/SELECT/**/";
buf = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:buf, bodyonly:TRUE );
if( isnull( res ) ) exit( 0 );

if( "Database error in WoltLab Burning Board" >< res && "Invalid SQL: SELECT * FROM" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
