#######################################################################
# OpenVAS Vulnerability Test
#
# rsync modules list
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
#######################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102003");
  script_version("2020-11-10T15:30:28+0000");
  script_tag(name:"last_modification", value:"2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2009-06-23 09:27:52 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("rsync modules list");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2009 LSS");
  script_dependencies("gb_rsync_remote_detect.nasl");
  script_require_ports("Services/rsync", 873);
  script_mandatory_keys("rsync/remote/detected");

  script_tag(name:"summary", value:"This script lists all modules available from particular rsync daemon.

  It's based on csprotocol.txt from the rsync source tree.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("rsync_func.inc");
include("port_service_func.inc");

port = rsync_get_port( default:873 );

# nb: It seems some rsync servers needs a short break between each connection.
# Depending on the scheduler VTs it could be possible that gb_rsync_remote_detect.nasl
# was running directly before so doing another sleep here.
sleep( 2 );

soc = rsync_connect( port:port );
if( ! soc )
  exit( 0 );

modules = rsync_get_module_list( soc:soc );
close( soc );
if( ! modules )
  exit( 0 );

report = 'Available rsync modules: \n\n';

foreach line( modules ) {

  line = chomp( line );

  ar = split( line, sep:'\t', keep:FALSE );

  module = chomp( ar[0] );
  dsc    = chomp( ar[1] );
  if( isnull( dsc ) )
    dsc = "No Description provided";

  # nb: It seems some rsync servers needs a short break between each connection
  # (the one done by rsync_get_module_list and rsync_authentication_required).
  sleep( 2 );
  auth = rsync_authentication_required( module:module, port:port );

  report += '  ' + module + '\t(' + dsc + '; authentication: ' + auth + ')\n';
  if( ! modules_list )
    modules_list = module;
  else
    modules_list += ' ' + module;
}

set_kb_item( name:"rsync/" + port + "/modules", value:modules_list );
set_kb_item( name:"rsync/modules_in_kb", value:TRUE );
log_message( port:port, data:report );

exit( 0 );
