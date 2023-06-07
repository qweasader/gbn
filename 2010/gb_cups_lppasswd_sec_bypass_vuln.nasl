###############################################################################
# OpenVAS Vulnerability Test
#
# CUPS 'lppasswd' Tool Localized Message String Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800488");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0393");
  script_name("CUPS 'lppasswd' Tool Localized Message String Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_cups_detect.nasl");
  script_mandatory_keys("CUPS/installed");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/USN-906-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38524");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=558460");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to gain
  privileges via a file that contains crafted localization data with format string specifiers.");

  script_tag(name:"affected", value:"CUPS versions 1.2.x, 1.3.x and 1.4.x.");

  script_tag(name:"insight", value:"The flaw is due to error within the '_cupsGetlang()' function,
  as used by 'lppasswd.c' in 'lppasswd', relies on an environment variable to determine the file
  that provides localized message strings.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"CUPS (Common UNIX Printing System) Service is prone to a
  security bypass vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+")
  exit( 0 ); # Version is not exact enough

if( version_in_range( version:vers, test_version:"1.4.0", test_version2:"1.4.1" ) ||
    version_in_range( version:vers, test_version:"1.2.0", test_version2:"1.2.2" ) ||
    version_in_range( version:vers, test_version:"1.3.0", test_version2:"1.3.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"N/A" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
