# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810612");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-03-13 12:06:29 +0530 (Mon, 13 Mar 2017)");
  script_name("Adobe Flash Player Within Google Chrome Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl", "lsc_options.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_exclude_keys("win/lsc/disable_wmi_search");

  script_xref(name:"URL", value:"https://helpx.adobe.com/flash-player/kb/flash-player-google-chrome.html");

  script_tag(name:"summary", value:"SMB login-based detection of Adobe Flash Player within Google Chrome.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("wmi_file.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");

infos = kb_smb_wmi_connectinfo();
if( ! infos )
  exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle )
  exit( 0 );

fileList = wmi_file_fileversion( handle:handle, dirPathLike:"%google%chrome%", fileName:"pepflashplayer", fileExtn:"dll", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) ) {
  exit( 0 );
}

checkduplicate = ""; # nb: To make openvas-nasl-lint happy...
checkduplicate_path = "";

foreach filePath( keys( fileList ) ) {

  vers = fileList[filePath];

  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ) ) {

    # wmi_file_fileversion returns the pepflashplayer.dll filename so we're stripping it away
    # to keep only the install location path
    location = filePath - "\pepflashplayer.dll";

    if( version[1] + ", " >< checkduplicate && location + ", " >< checkduplicate_path )
      continue;

    # Assign the detected version value to checkduplicate so as to check in next loop iteration
    checkduplicate += version[1] + ", ";
    checkduplicate_path += location + ", ";

    set_kb_item( name:"adobe/flash_player/detected", value:TRUE );
    set_kb_item( name:"AdobeFlashPlayer/Chrome/Win/Ver", value:version[1] );

    cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_player_chrome:" );
    if( ! cpe )
      cpe = "cpe:/a:adobe:flash_player_chrome";

    register_product( cpe:cpe, location:location, port:0, service:"smb-login" );
    log_message( data:build_detection_report( app:"Adobe Flash Player within Google Chrome",
                                              version:version[1],
                                              install:location,
                                              cpe:cpe,
                                              concluded:version[0] ) );
  }
}

exit( 0 );
