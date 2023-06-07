# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812213");
  script_version("2023-03-24T10:19:42+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-24 10:19:42 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2017-11-07 18:05:25 +0530 (Tue, 07 Nov 2017)");
  script_name("Norton Remove and Reinstall Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_wmi_access.nasl", "lsc_options.nasl");
  script_mandatory_keys("WMI/access_successful");
  script_exclude_keys("win/lsc/disable_wmi_search");

  script_tag(name:"summary", value:"SMB login-based detection of Norton Remove and Reinstall.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");

if( get_kb_item( "win/lsc/disable_wmi_search" ) )
  exit( 0 );

infos = kb_smb_wmi_connectinfo();
if( ! infos )
  exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle )
  exit( 0 );

query = 'Select Manufacturer, Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'NRnR' + raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) + 'exe' + raw_string(0x22);
appConfirm = wmi_query( wmi_handle:handle, query:query );
wmi_close( wmi_handle:handle );

if( "Symantec Corporation" >< appConfirm ) {
  version = eregmatch( pattern:"Symantec Corporation\|(.*)rnr.exe.?([0-9.]+)", string:appConfirm );
  if( version[2] ) {
    if( version[1] ) {
      path = version[1];
    } else {
      path = "Could not find the install location from registry";
    }

    set_kb_item( name:"Norton/Remove/Reinstall/Win/Ver", value:version[2] );

    cpe = build_cpe( value:version[2], exp:"^([0-9.]+)", base:"cpe:/a:norton:remove_%26_reinstall:" );
    if( ! cpe )
      cpe = "cpe:/a:norton:remove_%26_reinstall ";

    register_product( cpe:cpe, location:path, port:0, service:"smb-login" );

    log_message( data:build_detection_report( app:"Norton Remove and Reinstall",
                                              version:version[2],
                                              install:path,
                                              cpe:cpe,
                                              concluded:version[2] ) );
  }
}

exit( 0 );
