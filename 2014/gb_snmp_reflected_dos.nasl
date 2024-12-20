# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105062");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("SNMP GETBULK Reflected DRDoS");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-07-16 12:23:32 +0200 (Wed, 16 Jul 2014)");
  script_category(ACT_ATTACK);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("snmp_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/detected");

  script_xref(name:"URL", value:"http://www.darkreading.com/attacks-breaches/snmp-ddos-attacks-spike/d/d-id/1269149");

  script_tag(name:"impact", value:"Successfully exploiting this vulnerability allows attackers to
  cause denial-of-service conditions against remote hosts.");

  script_tag(name:"vuldetect", value:"Send an SNMP GetBulk request and check the response.");

  script_tag(name:"solution", value:"Disable the SNMP service on the remote host if you do not use it or
  restrict access to this service.");

  script_tag(name:"summary", value:"The remote SNMP daemon allows distributed reflection and
  amplification (DRDoS) attacks.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port( default:161 );

community = snmp_get_community( port:port );
if( ! community ) community = "public";

soc = open_sock_udp( port );
if( ! soc ) exit( 0 );

len = strlen( community );
len = len % 256;

#  snmpbulkget -v2c -Cn0 -Cr2500 -Os -c <community> <target> 1.3.6.1.2.1

req = raw_string( 0x30, 0x27, 0x02, 0x01, 0x01, 0x04, len,  community,  0xa5, 0x1a, 0x02,
                  0x04, 0x07, 0x7b, 0xce, 0x7a, 0x02, 0x01, 0x00, 0x02, 0x02, 0x09, 0xc4,
                  0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05,
                  0x00 );

send( socket:soc, data:req );
res = recv( socket:soc, length:65535, timeout:5 );
close( soc );
if( ! res ) exit( 0 );

if( strlen( res ) >= ( strlen( req ) * 8 ) ) {
  report = 'By sending an SNMP GetBulk request of ' + strlen( req ) + ' bytes, we received a response of ' +  strlen( res ) + ' bytes.' ;
  security_message( port:port, proto:'udp', data:report );
  exit( 0 );
}

exit( 99 );
