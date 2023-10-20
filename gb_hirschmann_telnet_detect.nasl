# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108312");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-11 09:03:31 +0100 (Mon, 11 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Hirschmann Devices Detection (Telnet)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/hirschmann/device/detected");

  script_tag(name:"summary", value:"This script performs Telnet based detection of Hirschmann Devices.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");
include("telnet_func.inc");
include("host_details.inc");

port   = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );
if( ! banner )
  exit( 0 );

# Copyright (c) 2011-2017 Hirschmann Automation and Control GmbH
if( "Hirschmann Automation and Control GmbH" >< banner ) {

  set_kb_item( name:"hirschmann_device/detected", value:TRUE );
  set_kb_item( name:"hirschmann_device/telnet/detected", value:TRUE );
  set_kb_item( name:"hirschmann_device/telnet/port", value:port );

  fw_version    = "unknown";
  product_name  = "unknown";
  platform_name = "unknown";

  # MACH Rugged Switch Release L2P-09.0.12
  # MACH Release L2P-09.0.04
  # RSP35 Release HiOS-3S-07.0.00
  # Railswitch Release L2E-09.0.12
  rls_banner = egrep( pattern:" Release ", string:banner );
  if( rls_banner ) {
    rls_banner = ereg_replace( pattern:"^(\s+)", replace:"", string:rls_banner );
    rls_banner = chomp( rls_banner );
    vers_prod_nd_model = eregmatch( pattern:"([^\r\n]+) Release ([0-9a-zA-Z]+)-([0-9a-zA-Z]+-)?([0-9.]+)", string:rls_banner );
    if( vers_prod_nd_model ) {
      product_name = vers_prod_nd_model[1];
      fw_version   = vers_prod_nd_model[4];
      if( vers_prod_nd_model[3] ) {
        platform_name  = vers_prod_nd_model[2] + "-";
        platform_name += ereg_replace( pattern:"-$", string:vers_prod_nd_model[3], replace:"" );
      } else {
        platform_name = vers_prod_nd_model[2];
      }
      set_kb_item( name:"hirschmann_device/telnet/" + port + "/concluded", value:vers_prod_nd_model[0] );
    } else {
      set_kb_item( name:"hirschmann_device/telnet/" + port + "/concluded", value:bin2string( ddata:rls_banner, noprint_replacement:'' ) );
    }
  } else {
    set_kb_item( name:"hirschmann_device/telnet/" + port + "/concluded", value:bin2string( ddata:banner, noprint_replacement:'' ) );
  }
  set_kb_item( name:"hirschmann_device/telnet/" + port + "/fw_version", value:fw_version );
  set_kb_item( name:"hirschmann_device/telnet/" + port + "/product_name", value:product_name );
  set_kb_item( name:"hirschmann_device/telnet/" + port + "/platform_name", value:platform_name );

  # Base-MAC   :  AA:00:11:22:33:44
  if( mac = eregmatch( pattern:"Base-MAC[ ]+:[ ]+([0-9a-fA-F:]{17})", string:banner ) ) {
    register_host_detail( name:"MAC", value:mac[1], desc:"Get the MAC Address via Hirschmann Telnet banner" );
    replace_kb_item( name:"Host/mac_address", value:mac[1] );
  }
}

exit( 0 );
