# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112138");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-11-23 11:04:05 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of the Greenbone Security Manager (GSM) /
  Greenbone OS (GOS).");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port( default:161 );

if( ! sysdesc = snmp_get_sysdescr( port:port ) )
  exit ( 0 );

if( concl = egrep( pattern:"^Greenbone (Security Manager|Enterprise Appliance)", string:sysdesc, icase:FALSE ) ) {

  concluded = "    " + chomp( concl );
  concludedOID = "    1.3.6.1.2.1.1.1.0 (sysDescr)";

  # This OID should contain both the GSM type and GOS version but was only available on older GOS
  # versions. TODO: Check VTD-1687
  info_oid = "1.3.6.1.2.1.1.5.0";
  oid_res = snmp_get( port:port, oid:info_oid );

  set_kb_item( name:"greenbone/gos/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/snmp/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/snmp/port", value:port );

  # nb: Keep in sync with the pattern in gb_greenbone_os_consolidation.nasl
  type_nd_vers = eregmatch( pattern:"^([0-9]+|TRIAL|DEMO|ONE|MAVEN|150V|EXPO|25V|CE|CENO|DECA|TERA|PETA|EXA)-([0-9\-]+)", string:oid_res );
  if( ! isnull( type_nd_vers[1] ) && ! isnull( type_nd_vers[2] ) ) {
    gsm_type = type_nd_vers[1];
    set_kb_item( name:"greenbone/gsm/snmp/" + port + "/type", value:gsm_type );
    gos_ver = str_replace( string:type_nd_vers[2], find:"-", replace:"." );
    set_kb_item( name:"greenbone/gos/snmp/" + port + "/version", value:gos_ver );
    concluded = '\n    ' + concluded;
    concludedOID = '\n    ' + concludedOID;
  }

  set_kb_item( name:"greenbone/gos/snmp/" + port + "/concludedOID", value:concludedOID );
  set_kb_item( name:"greenbone/gos/snmp/" + port + "/concluded", value:concluded );
}

exit( 0 );
