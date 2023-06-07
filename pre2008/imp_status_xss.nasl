###############################################################################
# OpenVAS Vulnerability Test
#
# Horde IMP status.php3 XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

CPE = "cpe:/a:horde:imp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15616");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4444");
  script_cve_id("CVE-2002-0181");
  script_xref(name:"OSVDB", value:"5345");
  script_name("Horde IMP status.php3 XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("imp_detect.nasl");
  script_mandatory_keys("horde/imp/detected");

  script_tag(name:"solution", value:"Upgrade to Horde IMP version 2.2.8 or later.");

  script_tag(name:"summary", value:"Horde IMP is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"insight", value:"The status.php3 script is vulnerable to an XSS attack since
  information passed to it is not properly sanitized.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/status.php3?script=<script>vt-test</script>" ;

if( http_vuln_check( port:port, url:url, pattern:'<script>vt-test</script>', check_header:TRUE ) ) {
  report = http_report_vuln_url( url:url, port:port );
  security_message( port:port, data:url );
}

exit( 0 );
