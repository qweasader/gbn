# OpenVAS Vulnerability Test
# Description: Zope Installation Path Disclosure
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11234");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5806");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Zope Installation Path Disclosure");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Web Servers");
  script_dependencies("gb_zope_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("zope/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Zope 2.5.1b1 / 2.6.0b1 or later.");

  script_tag(name:"summary", value:"The remote web server contains the Zope application server that is prone to
  information disclosure.");

  script_tag(name:"insight", value:"There is a minor security problem in all releases of Zope prior to
  version 2.5.1b1 - they reveal the installation path when an invalid
  XML RPC request is sent.");

  exit(0);
}

CPE = "cpe:/a:zope:zope";

include("http_func.inc");
include("misc_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! get_app_location( cpe: CPE, port: port, nofork: TRUE ) )
  exit( 0 );

if( ! s = http_open_socket( port ) )
  exit( 0 );

vt_strings = get_vt_strings();

# The proof of concept request was:
# POST /Documentation/comp_tut HTTP/1.0
# Host: localhost
# Content-Type: text/xml
# Content-length: 93
#
# <?xml version="1.0"?>
# <methodCall>
# <methodName>objectIds</methodName>
# <params/>
# </methodCall>
#
# but it does not seem to be necessary IIRC.

url = "/Foo/Bar/" + vt_strings["default"];
req = http_post(port: port, item: url);
send(socket: s, data: req);
a = http_recv(socket: s);
http_close_socket(s);

if (egrep(string: a, pattern: "(File|Bobo-Exception-File:) +(/[^/]*)*/[^/]+.py")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
