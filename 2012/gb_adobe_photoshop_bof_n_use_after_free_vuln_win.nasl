###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Photoshop BOF and Use After Free Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802782");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-2027", "CVE-2012-2028", "CVE-2012-2052", "CVE-2012-0275");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-05-15 15:41:49 +0530 (Tue, 15 May 2012)");
  script_name("Adobe Photoshop BOF and Use After Free Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48457/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52634");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53421");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53464");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55372");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027046");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-11.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Photoshop version prior to CS6 on Windows.");

  script_tag(name:"insight", value:"The flaws are caused by

  - An insufficient input validation while decompressing TIFF images.

  - An input sanitisation error when parsing TIFF images can be exploited
    to cause a heap-based buffer overflow via a specially crafted file.");

  script_tag(name:"summary", value:"Adobe Photoshop is prone to buffer overflow and use after free vulnerabilities.");

  script_tag(name:"solution", value:"Apply the patch for Adobe Photoshop CS5 and CS5.1,
  or upgrade to Adobe Photoshop version CS6 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:adobe:photoshop_cs5",
                      "cpe:/a:adobe:photoshop_cs5.1" );

if( ! infos = get_app_version_and_location_from_list( cpe_list:cpe_list, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

## Adobe Photoshop CS5 (12.0.5) and CS5.1 (12.1.1)
if( version_is_less( version:vers, test_version:"12.0.5" ) ) {
  installed = "CS5 " + vers;
  fixed = "CS5 12.0.5";
}

if( vers =~ "^12\.1" ) {
  if( version_is_less( version:vers, test_version:"12.1.1" ) ) {
    installed = "CS5.1 " + vers;
    fixed = "CS5.1 12.1.1";
  }
}

if( fixed ) {
  report = report_fixed_ver( installed_version:installed, fixed_version:fixed, install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
