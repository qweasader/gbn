###############################################################################
# OpenVAS Vulnerability Test
#
# Tiki Wiki CMS Groupware multiple input validation vulnerabilities
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
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

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14364");
  script_version("2022-05-12T09:32:01+0000");
  script_cve_id("CVE-2004-1923", "CVE-2004-1924", "CVE-2004-1925",
                "CVE-2004-1926", "CVE-2004-1927", "CVE-2004-1928");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10100");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Tiki Wiki CMS Groupware < 1.8.2 Multiple Input Validation Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_mandatory_keys("TikiWiki/installed");

  script_tag(name:"solution", value:"Update to version 1.8.2 or later.");

  script_tag(name:"impact", value:"These vulnerabilities may allow a remote attacker to carry out
  various attacks such as path disclosure, cross-site scripting, HTML injection, SQL injection,
  directory traversal, and arbitrary file upload.");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to multiple vulnerabilities in
  various modules of the application.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.8.2" ) ) {
   report = report_fixed_ver( installed_version:vers, fixed_version:"1.8.2" );
   security_message( port:port, data:report );
   exit( 0 );
}

exit( 99 );
