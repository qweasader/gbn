# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105189");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-29 15:29:06 +0100 (Thu, 29 Jan 2015)");
  script_name("Exim Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("smtpserver_detect.nasl");
  script_mandatory_keys("smtp/banner/available");

  script_tag(name:"summary", value:"The script sends a connection request to the
  server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");
include("cpe.inc");
include("misc_func.inc");
include("port_service_func.inc");

ports = smtp_get_ports();

foreach port( ports ) {

  banner = smtp_get_banner( port:port );

  quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
  noop = get_kb_item( "smtp/fingerprints/" + port + "/noop_banner" );
  help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
  rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );

  if( "ESMTP Exim" >< banner || ( "closing connection" >< quit &&
      "OK" >< noop && "Commands supported:" >< help && "Reset OK" >< rset ) ) {

    vers = "unknown";
    install = port + "/tcp";

    version = eregmatch( pattern:'ESMTP Exim ([0-9.]+(_[0-9]+)?)', string:banner );
    if( version[1] )
      vers = version[1];

    if( "_" >< vers )
      vers = str_replace( string:vers, find:"_", replace:"." );

    set_kb_item( name:"exim/installed", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/exim", value:vers );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:exim:exim:" );
    if( ! cpe )
      cpe = "cpe:/a:exim:exim";

    register_product( cpe:cpe, location:install, port:port, service:"smtp" );

    log_message( data:build_detection_report( app:"Exim",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:banner ),
                                              port:port );
  }
}

exit( 0 );
