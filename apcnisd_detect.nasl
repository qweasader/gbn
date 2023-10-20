# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100292");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-05 19:43:01 +0200 (Mon, 05 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("apcupsd / apcnisd Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service6.nasl");
  script_require_ports("Services/apcupsd", 3551, 7000);

  script_xref(name:"URL", value:"http://www.apcupsd.com/");

  script_tag(name:"summary", value:"This host is running apcupsd or apcnisd.

  apcupsd and apcnisd can be used for power management and controlling of APC's UPS models.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("cpe.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("dump.inc");

ports = service_get_ports( default_port_list:make_list( 3551, 7000 ), proto:"apcupsd" );
foreach port( ports ) {

  soc = open_sock_tcp(port);
  if( ! soc )
    continue;

  req  = raw_string( 0x00, 0x06 );
  req += string( "status" );

  send( socket:soc, data:req );
  buf = recv( socket:soc, length:4096 );
  close( soc );

  if( "APC" >< buf && ( "STATUS" >< buf || "MODEL" >< buf ) ) {

    version = "unknown";
    os      = "unknown";
    os_line = "";
    concl   = "";
    install = port + "/tcp";
    set_kb_item( name:"apcupsd/detected", value:TRUE );

    service_register( port:port, proto:"apcnisd" );

    lines = split( buf, keep:FALSE );
    foreach line( lines ) {

      line = bin2string( ddata:line, noprint_replacement:" " );
      extra += line + '\n';

      # RELEASE  : 3.10.17
      vers = eregmatch( string:line, pattern:"RELEASE *: *([0-9.]+)", icase:FALSE );
      if( version == "unknown" && vers[1] ) {
        version = vers[1];
        concl   = vers[0];
      }

      # *VERSION  : 3.10.17 (18 March 2005) debian
      # nb: Newer releases like the following below are only using the VERSION line
      # .VERSION  : 3.14.10 (13 September 2011) debian
      # *VERSION  : 3.14.12 (29 March 2014) debian
      # (VERSION  : 3.14.14 (31 May 2016) debian
      # (VERSION  : 3.14.14 (31 May 2016) redhat
      _os_line = eregmatch( string:line, pattern:"VERSION *: *([0-9.]+) \([^)]+\) ?(.+)?", icase:FALSE );
      if( _os_line[2] ) {
        os = tolower( _os_line[2] );
        os_line = _os_line[0];
      }

      if( version == "unknown" && _os_line[1] ) {
        version = _os_line[1];
        concl   = _os_line[0];
      }
    }

    if( os != "unknown" ) {
      if( "debian" >< os )
        os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:"apcupsd Banner", port:port, banner:os_line, desc:"apcupsd / apcnisd Detection", runs_key:"unixoide" );
      else if( "redhat" >< os )
        os_register_and_report( os:"Red Hat Enterprise Linux / CentOS / Fedora", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:"apcupsd Banner", port:port, banner:os_line, desc:"apcupsd / apcnisd Detection", runs_key:"unixoide" );
      else
        os_register_unknown_banner( banner:os_line, banner_type_name:"apcupsd Banner", banner_type_short:"apcupsd_banner", port:port );
    }

    register_and_report_cpe( app:"apcupsd / apcnisd", ver:version, base:"cpe:/a:apc:apcupsd:", expr:"([0-9.]+)", regPort:port, insloc:install, concluded:concl, regService:"apcupsd", extra:extra );
  }
}

exit( 0 );
