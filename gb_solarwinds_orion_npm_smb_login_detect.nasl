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
  script_oid("1.3.6.1.4.1.25623.1.0.107408");
  script_version("2021-10-27T09:07:12+0000");
  script_tag(name:"last_modification", value:"2021-10-27 09:07:12 +0000 (Wed, 27 Oct 2021)");
  script_tag(name:"creation_date", value:"2018-12-08 12:31:03 +0100 (Sat, 08 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("SolarWinds Orion Network Performance Monitor (NPM) Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of the SolarWinds Orion Network
  Performance Monitor (NPM).");

  exit(0);
}

include( "smb_nt.inc" );
include( "host_details.inc" );
include( "secpod_smb_func.inc" );

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch )
  exit( 0 );

if( "x86" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" );
} else if( "x64" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" );
}

if( isnull( key_list ) )
  exit( 0 );

foreach key( key_list ) {
  foreach item( registry_enum_keys( key:key ) ) {

    appName = registry_get_sz( key:key + item, item:"DisplayName" );
    if( ! appName || appName !~ "SolarWinds Orion Network Performance Monitor" )
      continue;

    concluded  = 'Registry Key:   ' + key + item + '\n';
    concluded += 'DisplayName:    ' + appName + '\n';
    location = "unknown";
    version = "unknown";

    loc = registry_get_sz( key:key + item, item:"InstallLocation" );
    if( loc )
      location = loc;

    # DisplayName:    SolarWinds Orion Network Performance Monitor 2020.2.6
    # DisplayVersion: 120.2.50073.6
    # because of this the DisplayName takes precedence below to avoid a false version extraction.
    #
    # Older versions had the following:
    # DisplayName:    SolarWinds Orion Network Performance Monitor v12.4
    # DisplayVersion: 12.4.5200.0
    vers = eregmatch( pattern:"SolarWinds Orion Network Performance Monitor ([0-9.]+)", string:appName );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
    } else {
      if( vers = registry_get_sz( key:key + item, item:"DisplayVersion" ) ) {
        version = vers;
        concluded += 'DisplayVersion: ' + vers + '\n';
      }
    }

    set_kb_item( name:"solarwinds/orion/npm/detected", value:TRUE );
    set_kb_item( name:"solarwinds/orion/npm/smb/detected", value:TRUE );
    set_kb_item( name:"solarwinds/orion/npm/smb/x86/version", value:version );
    set_kb_item( name:"solarwinds/orion/npm/smb/path", value:location );
    set_kb_item( name:"solarwinds/orion/npm/smb/concluded", value:concluded );

    exit( 0 );
  }
}

exit( 0 );
