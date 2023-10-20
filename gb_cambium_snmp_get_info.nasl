# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140247");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-04-11 17:39:31 +0200 (Tue, 11 Apr 2017)");
  script_name("Cambium Device Get SNMP Information Detection");

  script_tag(name:"summary", value:"This script request some information from the remote Cambium device via SNMP.");

  script_tag(name:"qod_type", value:"remote_active");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("snmp_func.inc");
include("misc_func.inc");
include("list_array_func.inc");

if( ! defined_func( "snmpv3_get" ) ) exit( 0 );

port    = snmp_get_port(default:161);
sysdesc = snmp_get_sysdescr(port:port);
if(!sysdesc) exit(0);
if( "Cambium" >!< sysdesc ) exit( 0 );

check_oids = make_array( "snmpSystemName",                 "1.3.6.1.4.1.17713.21.3.5.3.0",
                         "snmpSystemDescription",          "1.3.6.1.4.1.17713.21.3.5.4.0",
                         "cambiumSystemUptime",            "1.3.6.1.4.1.17713.21.1.1.4.0",
                         "cambiumUbootVersion",            "1.3.6.1.4.1.17713.21.1.1.14.0",
                         "snmpReadOnlyCommunity",          "1.3.6.1.4.1.17713.21.3.5.1.0",
                         "snmpReadWriteCommunity",         "1.3.6.1.4.1.17713.21.3.5.2.0",
                         "snmpTrapCommunity",              "1.3.6.1.4.1.17713.21.3.5.6.0",
                         "snmpTrapEntryIP",                "1.3.6.1.4.1.17713.21.3.5.7.1.2.0",
                         "wirelessRadiusServerInfo",       "1.3.6.1.4.1.17713.21.3.8.5.5.0",
                         "wirelessRadiusServerPort",       "1.3.6.1.4.1.17713.21.3.8.6.1.1.3.0",
                         "wirelessRadiusServerSecret",     "1.3.6.1.4.1.17713.21.3.8.6.1.1.4.0",
                         "wirelessRadiusUsername",         "1.3.6.1.4.1.17713.21.3.8.5.8.0",
                         "wirelessRadiusPassword",         "1.3.6.1.4.1.17713.21.3.8.5.9.0",
                         "wirelessInterfaceSSID",          "1.3.6.1.4.1.17713.21.3.8.2.2.0",
                         "wirelessInterfaceEncryptionKey", "1.3.6.1.4.1.17713.21.3.8.2.4.0",
                         "wirelessInterfaceEncryption",    "1.3.6.1.4.1.17713.21.3.8.2.3.0",
                         "networkWanPPPoEService",         "1.3.6.1.4.1.17713.21.3.4.3.13.0",
                         "networkWanPPPoEUsername",        "1.3.6.1.4.1.17713.21.3.4.3.10.0",
                         "networkWanPPPoEPassword",        "1.3.6.1.4.1.17713.21.3.4.3.11.0"
                       );

foreach check ( keys( check_oids ) )
{
  oid = check_oids[ check ];

  res = snmp_get( port:port, oid:oid );
  if( res  )
   res_array[ check  ] = res;
}

if( ! is_array( res_array ) )
  exit( 0 );

#  cambiumSystemUptime          : 0000:07:06:40
#  cambiumUbootVersion          : U-Boot 9342_PX 1.1.4.e (Nov 3 2016 - 16:50:32)
#  networkWanPPPoEPassword      : barfoo
#  networkWanPPPoEUsername      : foobar
#  snmpReadOnlyCommunity        : public
#  snmpSystemDescription        : Cambium Wi-Go
#  snmpSystemName               : Cambium Wi-Go
#  snmpTrapCommunity            : cambiumtrap
#  wirelessInterfaceEncryption  : 2
report = 'The remote host is a Cambium Device. The scanner was able to gather the following information via SNMP from the remote host:\n\n' + text_format_table( array:res_array );

log_message( port:port, proto:"udp", data:report );

exit( 0 );

