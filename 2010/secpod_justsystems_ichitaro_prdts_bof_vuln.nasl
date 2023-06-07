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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902041");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_cve_id("CVE-2009-4737");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("JustSystems Ichitaro Products 'RTF' Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_justsystems_ichitaro_prdts_detect.nasl");
  script_mandatory_keys("Ichitaro/Ichitaro_or_Viewer/Installed");

  script_xref(name:"URL", value:"http://www.justsystems.com/jp/info/js09002.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34403");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code on the
  vulnerable system or cause the application to crash.");

  script_tag(name:"affected", value:"JustSystems Ichitaro version 13, 2004 through 2009

  JustSystems Ichitaro viewer version 19.0.1.0 and prior");

  script_tag(name:"insight", value:"The flaw is due to improper bounds checking when opening the
  specially crafted RTF files.");

  script_tag(name:"summary", value:"JustSystems Ichitaro product(s) is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Update to the most recent version of Ichitaro.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list( "cpe:/a:ichitaro:ichitaro", "cpe:/a:justsystem:ichitaro_viewer");

if( ! infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if( "cpe:/a:ichitaro:ichitaro" >< cpe ) {
  if( version_in_range( version: vers, test_version: "2004", test_version2: "2009" ) || vers =~ "^13\." ) {
    report = report_fixed_ver( installed_version: vers, fixed_version: "Update to the most recent version of Ichitaro.", install_path: path );
    security_message( data: report, port: 0 );
    exit( 0 );
  }
}

else if( "cpe:/a:justsystem:ichitaro_viewer" >< cpe ) {
  if( version_is_less_equal( version: vers, test_version: "19.0.1.0" ) ) {
    report = report_fixed_ver( installed_version: vers, fixed_version: "Update to the most recent version of Ichitaro.", install_path: path );
    security_message( data: report, port: 0 );
    exit( 0 );
  }
}

exit( 99 );
