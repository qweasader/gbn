# SPDX-FileCopyrightText: 2008 Michel Arboi / Renaud Deraison
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# The HTTP IDS evasion mode comes from Whisker, by RFP.
# It has been moved to http_ids_evasion.nasl
#
# The TCP IDS evasion techniques are largely inspired by
# the work from Tom Ptacek and Tim Newsham.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80011");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 19:16:58 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("NIDS evasion");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2008 Michel Arboi / Renaud Deraison");
  script_family("Settings");

  script_add_preference(name:"TCP evasion technique", type:"radio", value:"none;split;injection;short ttl", id:1);
  script_add_preference(name:"Send fake RST when establishing a TCP connection", type:"checkbox", value:"no", id:2);

  script_tag(name:"summary", value:"This plugin configures the scanner for NIDS evasion (see the 'Prefs' panel).

  NIDS evasion options are useful if you want to determine the quality of the expensive NIDS you just bought.

  TCP Evasion techniques :

  - Split : send data one byte at a time. This confuses
  NIDSes which do not perform stream reassembly.

  - Injection : same as split, but malformed TCP packets
  containing bogus data are sent between normal packets.
  Here, a 'malformed' tcp packet means a legitimate TCP packet
  with a bogus checksum.
  This confuses NIDSes which perform stream reassembly but do
  not accurately verify the checksum of the packets or
  which do not determine if the remote host actually
  receives the packets seen.

  - Short TTL : same as split, but a valid TCP packets
  containing bogus data are sent between normal packets.
  These packets have a short (N-1), meaning that if
  the NIDS is on a gateway, it will see these packets
  go through, but they will not reach the target host.
  This confuses NIDSes which perform stream reassembly
  but do not accurately check if the packet can actually
  reach the remote host or which do not determine if the
  remote host actually receives the packets seen.

  - Fake RST : each time a connection is established, the
  scanner will send a RST packet with a bogus tcp checksum or
  a bogus ttl (depending on the options you chose above),
  thus making the IDS believe the connection was closed
  abruptly.
  This confuses badly written NIDSes which believe
  anything they see.

  Warning: those features are experimental and some options may result in false negatives!

  This plugin does not do any security check.");

  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

pref = script_get_preference( "TCP evasion technique" );
if( ! pref ) exit( 0 );
if( pref == "none" ) exit( 0 );
if( pref == "none;split;injection;short ttl" ) exit( 0 );

# Generic key for network.c of scanner/libs
set_kb_item( name:"NIDS/TCP/enabled", value:TRUE );

if( pref == "split" ) {
  set_kb_item( name:"NIDS/TCP/split", value:"yes" );

  if( ! get_kb_item( "/Settings/Whisker/NIDS" ) )
    set_kb_item( name:"/Settings/Whisker/NIDS", value:"9" );

  log_message( port:0, data:"TCP split NIDS evasion function is enabled. Some tests might run slowly and you may get some false negative results." );
}

if( pref == "injection" ) {
  set_kb_item( name:"NIDS/TCP/inject", value:"yes" );
  log_message( port:0, data:"TCP inject NIDS evasion function is enabled. Some tests might run slowly and you may get some false negative results." );
}

if( pref == "short ttl" ) {
  set_kb_item( name:"NIDS/TCP/short_ttl", value:"yes" );
  log_message( port:0, data:"TCP short ttl NIDS evasion function is enabled. Some tests might run slowly and you may get some false negative results." );
}

pref = script_get_preference( "Send fake RST when establishing a TCP connection" );
if( ! pref ) exit( 0 );
if( pref == "no" ) exit( 0 );

if( pref == "yes" ) {
  set_kb_item( name:"NIDS/TCP/fake_rst", value:"yes" );
  log_message( port:0, data:"TCP fake RST NIDS evasion function is enabled. Some tests might run slowly and you may get some false negative results." );
}

exit( 0 );
