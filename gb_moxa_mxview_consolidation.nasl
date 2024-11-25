# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125001");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2022-02-23 14:26:00 +0100 (Wed, 23 Feb 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa MXview Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Moxa MXview detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_moxa_mxview_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_moxa_mxview_smb_login_detect.nasl");
  script_mandatory_keys("moxa/mxview/detected");

  script_xref(name:"URL", value:"https://www.moxa.com/en/products/industrial-network-infrastructure/network-management-software/mxview-series");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item( "moxa/mxview/detected" ) )
  exit( 0 );

detected_version = "unknown";
install = "/";
extra = '\nDetection methods:\n';

foreach proto ( make_list( "smb-login", "http" ) ) {
  version_list = get_kb_list( "moxa/mxview/" + proto + "/*/version" );
  foreach vers( version_list ) {
    if( vers != "unknown" && detected_version == "unknown" ) {
      detected_version = vers;
      break;
    }
  }
}

cpe = build_cpe( value:detected_version, exp:"^([0-9.]+)", base:"cpe:/a:moxa:mxview:" );
if( ! cpe )
  cpe = "cpe:/a:moxa:mxview";

if( http_ports = get_kb_list( "moxa/mxview/http/port" ) ) {
  foreach port( http_ports ) {
    extra += '\n- HTTP(s) on port ' + port + "/tcp" + '\n\n';

    if( concluded_url = get_kb_item( "moxa/mxview/http/" + port + "/concludedUrl" ) )
      extra += '  Concluded from version/product identification location:\n  ' + concluded_url + '\n';

    register_product( cpe:cpe, port:port, service:"www" );
  }
}

if( concluded = get_kb_item( "moxa/mxview/smb-login/0/concluded" ) ) {
  extra += '\n- Local Detection via SMB login:\n\n';
  extra += concluded;

  if( insloc = get_kb_item( "moxa/mxview/smb-login/0/path" ) ) {
    extra += '  Location:       ' + insloc + '\n';
  }

  register_product( cpe:cpe, location:insloc, port:0, service:"smb-login" );
}

os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows",
                        desc:"Moxa MXview Detection Consolidation", runs_key:"windows" );

report = build_detection_report( app:"Moxa MXview",
                                 version:detected_version,
                                 cpe:cpe,
                                 install: install );

report += '\n' + extra;

log_message( port:0, data:chomp( report ) );

exit( 0 );
