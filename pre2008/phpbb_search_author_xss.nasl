###############################################################################
# OpenVAS Vulnerability Test
#
# phpBB < 2.0.10 Multiple Vulnerabilities
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13840");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2054", "CVE-2004-2055");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10738");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10753");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10754");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10883");
  script_xref(name:"OSVDB", value:"8164");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("phpBB < 2.0.10 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
  script_mandatory_keys("phpBB/installed");

  script_tag(name:"solution", value:"Update to version 2.0.10 or later.");

  script_tag(name:"summary", value:"phpBB is prone to multiple vulnerabilities.");

  script_tag(name:"affected", value:"phpBB prior to version 2.0.10.");

  script_tag(name:"insight", value:"The following flaws exist:

  - a flaw that allows a remote cross-site scripting (XSS) attack. This flaw exists because the
  application does not validate user-supplied input in the 'search_author' parameter.

  - a HTTP response splitting vulnerability which permits the injection of CRLF characters in the
  HTTP headers.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"2.0.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.10" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );