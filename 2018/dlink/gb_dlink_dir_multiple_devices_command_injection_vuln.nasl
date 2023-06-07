# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113142");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"creation_date", value:"2018-03-21 10:54:55 +0100 (Wed, 21 Mar 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-27 18:09:00 +0000 (Tue, 27 Mar 2018)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-6530");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DIR Routers OS Command Injection Vulnerability (Mar 2018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link Routers DIR-860L, DIR-865L, DIR-868L and DIR-880L are prone
  to an OS command injection vulnerability.");

  script_tag(name:"vuldetect", value:"The script checks if the target is an affected device running a
  vulnerable Firmware version.");

  script_tag(name:"insight", value:"The OS command injection is possible through the service parameter
  in soap.cgi.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute
  arbitrary OS commands, effectively gaining complete control over the target system.");

  script_tag(name:"affected", value:"D-Link DIR-860L through firmware version 1.10b04

  D-Link DIR-865L through firmware version 1.08b01

  D-Link DIR-868L through firmware version 1.12b04

  D-Link DIR-880L through firmware version 1.08b04");

  script_tag(name:"solution", value:"Update to DIR-860L 1.11, DIR-865L 1.10, DIR-868L 1.20 or
  DIR-880L 1.08b06 respectively.");

  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-860L/REVA/DIR-860L_REVA_FIRMWARE_PATCH_NOTES_1.11B01_EN_WW.pdf");
  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-865L/REVA/DIR-865L_REVA_FIRMWARE_PATCH_NOTES_1.10B01_EN_WW.pdf");
  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-868L/REVA/DIR-868L_REVA_FIRMWARE_PATCH_NOTES_1.20B01_EN_WW.pdf");
  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-880L/REVA/DIR-880L_REVA_FIRMWARE_PATCH_NOTES_1.08B06_EN_WW.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:d-link:dir-860l_firmware",
                      "cpe:/o:d-link:dir-865l_firmware",
                      "cpe:/o:d-link:dir-868l_firmware",
                      "cpe:/o:d-link:dir-880l_firmware" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe  = infos["cpe"];
port = infos["port"];

if( ! version = get_app_version( cpe:cpe, port:port ) )
  exit( 0 );

if( "dir-860l" >< cpe ) {
  device = "DIR-860L";
  fixed_ver = "1.11";
} else if( "dir-865l" >< cpe ) {
  device = "DIR-865L";
  fixed_ver = "1.10";
} else if( "dir-868l" >< cpe ) {
  device = "DIR-868L";
  fixed_ver = "1.20";
} else if( "dir-880l" >< cpe ) {
  device = "DIR-880L";
  fixed_ver = "1.08";
}

if( device && fixed_ver ) {
  if( version_is_less( version:version, test_version:fixed_ver ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:fixed_ver, extra:"The target device is a " + device );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
}

exit( 0 );
