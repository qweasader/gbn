###############################################################################
# OpenVAS Vulnerability Test
#
# FortiWeb Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105199");
  script_version("2022-03-16T12:33:22+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-16 12:33:22 +0000 (Wed, 16 Mar 2022)");
  script_tag(name:"creation_date", value:"2015-02-10 17:03:19 +0100 (Tue, 10 Feb 2015)");
  script_name("FortiWeb Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("fortinet/fortios/system_status");

  script_tag(name:"summary", value:"SSH login-based detection of FortiWeb.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

system = get_kb_item("fortinet/fortios/system_status");
if( !system || "FortiWeb" >!< system )
  exit( 0 );

cpe = "cpe:/a:fortinet:fortiweb";

model = eregmatch( string:system, pattern:'Version:(FortiWeb-[^ ]+)' );

if( ! isnull( model[1] ) )
{
  mod = model[1];
  mod = chomp( mod );
  set_kb_item( name:"fortiweb/model", value:mod );
}

vers = 'unknown';
version = eregmatch( string:system, pattern:"Version:FortiWeb-[^ ]* ([0-9.]+)," );

if( ! isnull( version[1] ) )
{
  ver = version[1];
  for( i = 0; i < strlen( ver ); i++ )
  {
    if( ver[i] == "." )
      continue;

    v += ver[ i ];

    if( i < ( strlen( ver ) - 1 ) )
      v += '.';

  }
  set_kb_item( name:"fortiweb/version", value:v );
  cpe += ':' + v;
  vers = v;
}

build = eregmatch( string:system, pattern:',build([^,]+)' );
if( ! isnull( build[1] ) )
{
  build = ereg_replace( string:build[1], pattern:'^0', replace:"" );
  set_kb_item( name:"fortiweb/build", value:build );
}

patch = eregmatch( string:system, pattern:"Patch ([0-9]+)" );
if( ! isnull( patch[1] ) )
{
  set_kb_item( name:"fortiweb/patch", value:patch[1]);
}

register_product( cpe:cpe, location:"ssh", service:"ssh" );

report = 'Detected FortiWeb (ssh)\n\n' +
         'Version: ' + vers + '\n';

if( mod )
  report += 'Model:   ' + mod + '\n';

if( !isnull( build ) )
  report += 'Build:   ' + build + '\n';

report += 'CPE:     ' + cpe;

log_message( port:0, data:report );

exit( 0 );
