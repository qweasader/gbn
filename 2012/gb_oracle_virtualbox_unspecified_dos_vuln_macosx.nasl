###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle VM VirtualBox Unspecified Denial of Service Vulnerability (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.803104");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-3221");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-10-19 15:10:56 +0530 (Fri, 19 Oct 2012)");
  script_name("Oracle VM VirtualBox Unspecified Denial of Service Vulnerability (Mac OS X)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2012.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56045");

  script_tag(name:"impact", value:"Successful exploitation allows local users to cause a Denial of Service.");

  script_tag(name:"affected", value:"Oracle VM VirtualBox version 3.2, 4.0 and 4.1 on Mac OS X.");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to a denial of service vulnerability.");

  script_tag(name:"solution", value:"Apply the patch.");

  script_tag(name:"insight", value:"Unspecified error in the VirtualBox Core subcomponent.

  Note: No further information is currently available.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

cpe_list = make_list( "cpe:/a:sun:virtualbox", "cpe:/a:oracle:vm_virtualbox" );

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_equal( version: vers, test_version: "4.1" ) ||
    version_is_equal( version: vers, test_version: "4.0" ) ||
    version_is_equal( version: vers, test_version: "3.2" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
