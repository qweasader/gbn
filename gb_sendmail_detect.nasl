# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800608");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sendmail / Sendmail Switch / SMI Sendmail Detection (SMTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/banner/available");

  script_tag(name:"summary", value:"SMTP based detection of Sendmail / Sendmail Switch / SMI
  Sendmail SMTP server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port( default:25 );
banner = smtp_get_banner( port:port );

quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
noop = get_kb_item( "smtp/fingerprints/" + port + "/noop_banner" );
help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );

# 220 mail.example.com ESMTP Sendmail Switch-3.3.4/Switch-3.3.4; Tue, 15 Jan 2019 15:20:46 +0900
# 220 mail.example.com ESMTP Sendmail Sentrion-MTA-4.0.2/Switch-3.3.4; Tue, 15 Jan 2019 12:53:21 +0900
# 220 mail.example.com ESMTP Sendmail 8.15.2/8.15.2; Tue, 15 Jan 2019 16:04:30 +0900 (JST)
# 220 mail.example.com Sendmail 5.61/SMI-4.1 ready at Wed, 31 Jan 96 15:59:02 -0800
# 220 mail.example.com ESMTP Sendmail AIX4.2/UCB 8.7; Fri, 11 Jan 2019 11:50:41 +0800 (TAIST)
# 220 smtp sendmail v8.12.11 (IBM AIX 4.3)
if( "Sendmail" >< banner || "220 smtp sendmail" >< banner || ( ( "This is sendmail version" >< help || "sendmail-bugs@sendmail.org" >< help || "HELP not implemented" >< help || "Syntax Error, command unrecognized" >< help ) &&
    "OK" >< noop && ( "Reset state" >< rset || "OK" >< rset ) && ( "closing connection" >< quit || "Closing connection" >< quit ) ) ) {

  version = "unknown";
  install = port + "/tcp";

  if( banner =~ "Sendmail.+/Switch-" ) {

    app = "Sendmail Switch";
    base_cpe = "cpe:/a:sendmail:sendmail_switch";
    vers = eregmatch( pattern:"Sendmail.+/Switch-([0-9.]+)", string:banner );
    if( vers[1] )
      version = vers[1];

    set_kb_item( name:"sendmail_switch/detected", value:TRUE );
    set_kb_item( name:"sendmail_switch/" + port + "/version", value:version );
    set_kb_item( name:"sendmail_switch/" + port + "/detected", value:TRUE );

  } else if( banner =~ "Sendmail.+/SMI-" ) {

    app = "SMI Sendmail";
    base_cpe = "cpe:/a:sun:smi_sendmail";
    vers = eregmatch( pattern:"Sendmail.+/SMI-([0-9.]+)", string:banner );
    if( vers[1] )
      version = vers[1];

    set_kb_item( name:"smi_sendmail/detected", value:TRUE );
    set_kb_item( name:"smi_sendmail/" + port + "/version", value:version );
    set_kb_item( name:"smi_sendmail/" + port + "/detected", value:TRUE );

  } else if( banner =~ "Sendmail.+/UCB " ) {

    app = "Sendmail UCB";
    base_cpe = "cpe:/a:sendmail:sendmail_ucb";
    vers = eregmatch( pattern:"Sendmail.+/UCB ([0-9.]+)", string:banner );
    if( vers[1] )
      version = vers[1];

    set_kb_item( name:"sendmail_ucb/detected", value:TRUE );
    set_kb_item( name:"sendmail_ucb/" + port + "/version", value:version );
    set_kb_item( name:"sendmail_ucb/" + port + "/detected", value:TRUE );

  } else {

    app = "Sendmail";
    base_cpe = "cpe:/a:sendmail:sendmail";

    vers = eregmatch( pattern:"ESMTP Sendmail ([0-9.]+)", string:banner );
    if( vers[1] )
      version = vers[1];

    if( version == "unknown" ) {
      vers = eregmatch( pattern:"This is sendmail version ([0-9.]+)", string:help );
      if( vers[1] )
        version = vers[1];
    }

    if( version == "unknown" ) {
      vers = eregmatch( pattern:"Sendmail ([0-9.]+)", string:help );
      if( vers[1] )
        version = vers[1];
    }

    if( version == "unknown" ) {
      vers = eregmatch( pattern:"smtp sendmail v([0-9.]+)", string:banner );
      if( vers[1] )
        version = vers[1];
    }

    set_kb_item( name:"sendmail/detected", value:TRUE );
    set_kb_item( name:"sendmail/" + port + "/version", value:version );
    set_kb_item( name:"sendmail/" + port + "/detected", value:TRUE );
  }

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:base_cpe + ":" );
  if( ! cpe )
    cpe = base_cpe;

  register_product( cpe:cpe, location:install, port:port, service:"smtp" );

  log_message( data:build_detection_report( app:app,
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            port:port );
}

exit( 0 );
