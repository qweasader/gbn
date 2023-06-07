###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Firepower Management Center Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105519");
  script_version("2020-11-25T07:02:22+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-11-25 07:02:22 +0000 (Wed, 25 Nov 2020)");
  script_tag(name:"creation_date", value:"2016-01-19 16:05:51 +0100 (Tue, 19 Jan 2016)");

  script_name("Cisco Firepower Management Center (FMC) Detection (SSH)");

  script_tag(name:"summary", value:"SSH based detection of Cisco Firepower Management Center (FMC).");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl", "gb_cisco_show_version.nasl");
  script_mandatory_keys("cisco_fire_linux_os/detected");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if( ! get_kb_item( "cisco_fire_linux_os/detected" ) )
  exit( 0 );

version = "unknown";
build = "unknown";
model = "unknown";

show_version = get_kb_item( "cisco/show_version" );
port = kb_ssh_transport();

# -------------------[ firepower ]--------------------
# Model                     : Cisco Firepower Management Center for VMWare (66) Version 6.6.1 (Build 91)
# UUID                      : 7708495a-1f26-11eb-9ca5-07846839c8a0
# Rules update version      : 2020-08-18-001-vrt
# VDB version               : 338
# ----------------------------------------------------
if( "Cisco Firepower Management Center" >< show_version ) {
  concluded = show_version;

  vers = eregmatch( pattern:"Version ([0-9.]+) \(Build ([0-9]+)\)", string:show_version );
  if( ! isnull( vers[1] ) )
    version = vers[1];

  if( ! isnull( vers[2] ) )
    build = vers[2];
} else {
  sock = ssh_login_or_reuse_connection();
  if( ! sock )
    exit( 0 );

  sf_version = ssh_cmd( socket:sock, cmd:"cat /etc/sf/sf-version" );

  close( sock );

  # Cisco Firepower Management Center for VMWare v6.4.0 (build 102) / Cisco Fire Linux OS v6.4.0 (build 2)
  if( "Cisco Firepower Management Center" >!< sf_version )
    exit( 0 );

  concluded = sf_version;

  if( "/ Cisco Fire Linux OS" >< sf_version ) {
    sf = split( sf_version, sep:"/", keep:FALSE );
    if( ! isnull( sf[0] ) )
      sf_version = sf[0];
  }

  vb = eregmatch( pattern:'v([^ ]+) \\(build ([^)]+)\\)', string:sf_version );

  if( ! isnull( vb[1] ) )
    version = vb[1];

  if( ! isnull( vb[2] ) )
    build = vb[2];
}

if( "for VMWare" >< concluded )
  model = "VM";
else {
  ms = concluded;
  ms = ereg_replace( string:ms, pattern:'(32|64)bit', replace:'' );
  _m = eregmatch( pattern:'Management Center ([^ v]+) v', string:ms );
  if( ! isnull( _m[1] ) )
    model = _m[1];
}

set_kb_item( name:"cisco/firepower_management_center/detected", value:TRUE );
set_kb_item( name:"cisco/firepower_management_center/ssh-login/port", value:port );
set_kb_item( name:"cisco/firepower_management_center/ssh-login/" + port + "/model", value:model );
set_kb_item( name:"cisco/firepower_management_center/ssh-login/" + port + "/version", value:version );
set_kb_item( name:"cisco/firepower_management_center/ssh-login/" + port + "/build", value:build );
set_kb_item( name:"cisco/firepower_management_center/ssh-login/" + port + "/concluded", value:concluded );

exit( 0 );
