# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108244");
  script_version("2023-08-08T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-08-08 05:06:11 +0000 (Tue, 08 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-09-25 10:52:11 +0200 (Mon, 25 Sep 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Get the MAC Address over SNMP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("SNMP");
  script_dependencies("snmp_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/detected");

  script_tag(name:"summary", value:"This script attempts to gather the MAC address of the target via
  SNMP.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("snmp_func.inc");

port = snmp_get_port( default:161 );

# Scanner needs to be build against libsnmp or have snmpget installed for extended SNMP
# functionality in e.g. snmp_func.inc.
# nb: This functions should be always there since openvas-scanner version 20.08.1 / via:
# https://github.com/greenbone/openvas-scanner/pull/594
if( defined_func( "snmpv3_get" ) ) {

  # The host could have multiple network interfaces, available in ifPhysAddress (1.3.6.1.2.1.2.2.1.6.x)
  # but currently we only want to know the MAC of the interface we're scanning.
  ip = get_host_ip();

  # First get the interface ID from ipAdEntIfIndex (1.3.6.1.2.1.4.20.1.2.IP)
  if( isnull( id = snmp_get( port:port, oid:"1.3.6.1.2.1.4.20.1.2." + ip ) ) ) exit( 0 );

  # Afterwards get the MAC from ifPysAddress and replace possible spaces with double points
  if( ! mac = snmp_get( port:port, oid:"1.3.6.1.2.1.2.2.1.6." + id ) ) exit( 0 );
  mac = str_replace( string:mac, find:" ", replace:":" );
  mac = eregmatch( pattern:"([0-9a-fA-F:]{17})", string:mac );
  if( ! isnull( mac[1] ) ) {
    register_host_detail( name:"MAC", value:mac[1], desc:"Get the MAC Address over SNMP" );
    replace_kb_item( name:"Host/mac_address", value:mac[1] );
  }
}

exit( 0 );
