# SPDX-FileCopyrightText: 2005 HD Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10674");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft's SQL UDP Info Query");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 HD Moore");
  script_family("Service detection");
  script_require_udp_ports(1434);

  script_tag(name:"solution", value:"If you are not running multiple instances of Microsoft SQL Server
  on the same machine, it is suggested you filter incoming traffic to this port.");

  script_tag(name:"summary", value:"It is possible to determine the remote MS SQL server version.

  Microsoft SQL server has a function wherein remote users can query the database server for the
  version that is being run. The query takes place over the same UDP port which handles the
  mapping of multiple SQL server instances on the same machine.

  CAVEAT: It is important to note that, after Version 8.00.194, Microsoft decided not to update
  this function. This means that the data returned by the SQL ping is inaccurate for newer releases
  of SQL Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

##
# data returned will look like:
#
#   xServerName;REDEMPTION;InstanceName;MSSQLSERVER;IsClustered;No;Version;8.00.194;tcp;1433;np;\\REDEMPTION\pipe\sql\query;;
#
##

# the magic info request packet
req = raw_string(0x02);

port = 1434;
if( ! get_udp_port_state( port ) ) exit( 0 );
soc = open_sock_udp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:req );
r = recv( socket:soc, length:4096 );
close( soc );
if( ! r ) exit( 0 );

set_kb_item( name:"MSSQL/UDP/Ping", value:TRUE );
r = strstr( r, "Server" );
r = str_replace( find:";", replace:" ", string:r );

if( r ) {

  report = string("The scanner has sent a MS SQL 'ping' request. The result was : \n\n", r);

  if( "version" >< tolower( r ) ) {
    version = eregmatch( pattern:"Version ([0-9.]+)", string:r );
    if( ! isnull( version[1] ) ) {
      set_kb_item( name:"mssql/remote_version", value:version[1] );
    }
  }

  service_register( port:port, ipproto:"udp", proto:"mssql", message:"A MS SQL Browser Service seems to be running on this port." );
  log_message( port:port, protocol:"udp", data:report );
  set_kb_item( name:"mssql/udp/1434", value:TRUE );
}

exit( 0 );
