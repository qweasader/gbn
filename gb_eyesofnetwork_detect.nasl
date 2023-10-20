# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108167");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-05-22 09:21:05 +0200 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Eyes Of Network (EON) Detection (Version)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_eyesofnetwork_detect_http.nasl", "gb_eyesofnetwork_detect_ssh.nasl",
                      "gb_eyesofnetwork_detect_snmp.nasl");
  script_mandatory_keys("eyesofnetwork/detected");

  script_tag(name:"summary", value:"The script reports a detected Eyes Of Network (EON) including the
  version number and exposed services.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

if( ! get_kb_item( "eyesofnetwork/detected" ) ) exit( 0 );

detected_version = "unknown";

foreach source( make_list( "ssh", "http", "snmp" ) ) {

  version_list = get_kb_list( "eyesofnetwork/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      set_kb_item( name:"eyesofnetwork/version", value:version );
    }
  }
}

if( detected_version != "unknown" ) {
  cpe = "cpe:/a:eyes_of_network:eyes_of_network:" + version;
} else {
  cpe = "cpe:/a:eyes_of_network:eyes_of_network";
}

location = "/";
extra = '\nDetection methods:\n';

if( http_port = get_kb_list( "eyesofnetwork/http/port" ) ) {
  foreach port( http_port ) {
    concluded = get_kb_item( "eyesofnetwork/http/" + port + "/concluded" );
    concludedUrl = get_kb_item( "eyesofnetwork/http/" + port + "/concludedUrl" );
    extra += "HTTP(s) on port " + port + '/tcp';
    if( concluded && concludedUrl ) {
      extra += '\nConcluded: ' + concluded + ' from URL: ' + concludedUrl + '\n';
    }
    register_product( cpe:cpe, location:location, port:port, service:"www" );
  }
}

if( ssh_port = get_kb_list( "eyesofnetwork/ssh/port" ) ) {
  foreach port( ssh_port ) {
    concluded = get_kb_item( "eyesofnetwork/ssh/" + port + "/concluded" );
    concludedFile = get_kb_item( "eyesofnetwork/ssh/" + port + "/concludedFile" );
    extra += "SSH on port " + port + '/tcp';
    if( concluded && concludedFile ) {
      extra += '\nConcluded: ' + concluded + ' from file: ' + concludedFile + '\n';
    }
    register_product( cpe:cpe, location:location, port:port, service:"ssh" );
  }
}

if( snmp_port = get_kb_list( "eyesofnetwork/snmp/port" ) ) {
  foreach port( snmp_port ) {
    concluded = get_kb_item( "eyesofnetwork/snmp/" + port + "/concluded" );
    concludedOID = get_kb_item( "eyesofnetwork/snmp/" + port + "/concludedOID" );
    extra += "SNMP on port " + port + '/udp';
    if( concluded && concludedOID ) {
      extra += 'via OID: ' + concludedOID + '\nConcluded from installed package: ' + concluded + '\n';
    }
    register_product( cpe:cpe, location:location, port:port, service:"snmp", proto:"udp" );
  }
}

if( api_version = get_kb_item( "eyesofnetwork/api/version" )) {
  extra += '\nAPI version: ' + api_version;
}

log_message( data:build_detection_report( app:"Eyes of Network (EON)",
                                          version:detected_version,
                                          install:location,
                                          cpe:cpe,
                                          extra:extra ),
                                          port:0 );

exit( 0 );
