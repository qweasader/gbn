# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112118");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-11-13 08:56:05 +0100 (Mon, 13 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("pfSense Detection (Version)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_pfsense_detect_http.nasl", "gb_pfsense_detect_ssh.nasl", "gb_pfsense_detect_snmp.nasl");
  script_mandatory_keys("pfsense/installed");

  script_tag(name:"summary", value:"The script reports a detected pfSense including the
  version number and exposed services.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

if( ! get_kb_item( "pfsense/installed" ) )
  exit( 0 );

detected_version = "unknown";
detected_patch   = "unknown";

foreach source( make_list( "ssh", "http", "snmp" ) ) {

  version_list = get_kb_list( "pfsense/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      set_kb_item( name:"pfsense/version", value:version );
    }
  }

  patch_list = get_kb_list( "pfsense/" + source + "/*/patch" );
  foreach patch( patch_list ) {
    if( patch != "unknown" && detected_patch == "unknown" ) {
      detected_patch = patch;
      set_kb_item( name:"pfsense/patch", value:patch );
    }
  }
}

if( detected_version != "unknown" ) {
  cpe = "cpe:/a:pfsense:pfsense:" + version;
  if( detected_patch != "unknown" )
    cpe += ":" + detected_patch;
} else {
  cpe = "cpe:/a:pfsense:pfsense";
}

location = "/";
extra = '\nDetection methods:\n';

if( http_port = get_kb_list( "pfsense/http/port" ) ) {
  foreach port( http_port ) {
    extra += '\nHTTP(s) on port ' + port + '/tcp';
    register_product( cpe:cpe, location:location, port:port, service:"www" );
  }
}

if( ssh_port = get_kb_list( "pfsense/ssh/port" ) ) {
  foreach port( ssh_port ) {
    extra += '\nSSH login on port ' + port + '/tcp';
    concluded = get_kb_item( "pfsense/ssh/" + port + "/concluded" );
    if( concluded )
      extra += '\nConcluded: ' + concluded + '\n';

    register_product( cpe:cpe, location:location, port:port, service:"ssh-login" );
  }
}

if( snmp_port = get_kb_list( "pfsense/snmp/port" ) ) {
  foreach port( snmp_port ) {
    extra += '\nSNMP on port ' + port + '/udp';
    concluded = get_kb_item( "pfsense/snmp/" + port + "/concluded" );
    if( concluded )
      extra += '\nConcluded from SNMP sysDescr OID: ' + concluded + '\n';

    register_product( cpe:cpe, location:location, port:port, service:"snmp", proto:"udp" );
  }
}

log_message( data:build_detection_report( app:"pfSense",
                                          version:detected_version,
                                          patch:detected_patch,
                                          install:location,
                                          cpe:cpe,
                                          extra:extra ),
                                          port:0 );

exit( 0 );
