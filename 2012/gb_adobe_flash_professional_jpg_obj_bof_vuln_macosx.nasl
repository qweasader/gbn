###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Professional JPG Object Processing BOF Vulnerability (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802785");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-0778");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-05-16 12:09:06 +0530 (Wed, 16 May 2012)");
  script_name("Adobe Flash Professional JPG Object Processing BOF Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47116/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53419");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027045");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-12.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_flash_professional_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Prof/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"Adobe Flash Professional version CS5.5.1(11.5.1.349) and prior on Mac OS X");
  script_tag(name:"insight", value:"The flaw is due to an error in 'Flash.exe' when allocating memory to
  process a JPG object using its image dimensions.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Professional version CS6 or later.");
  script_tag(name:"summary", value:"Adobe Flash Professional is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item( "Adobe/Flash/Prof/MacOSX/Version" );
if( ! vers )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"11.5.1.349" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"Upgrade to CS6 or later" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
