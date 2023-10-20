# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814305");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-05 16:30:44 +0530 (Mon, 05 Nov 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Telegram Desktop Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Telegram
  Desktop on Windows.

  The script logs in via WMI, searches for Telegram Desktop and gets the
  version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_exclude_keys("win/lsc/disable_wmi_search");

  exit(0);
}

include("wmi_file.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");

infos = kb_smb_wmi_connectinfo();
if( ! infos ) exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle ) exit( 0 );

fileList = wmi_file_fileversion( handle:handle, fileName:"Telegram", fileExtn:"exe", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) ) {
  exit( 0 );
}

foreach filePath( keys( fileList ) )
{
  location = filePath - "\telegram.exe";
  if("\tupdates\temp" >!< location)
  {
    telPath = location;
    vers = fileList[filePath];
    if( vers )
    {
      version = eregmatch( string:vers, pattern:"^([0-9.]+)");
      if(version[1])
      {
        set_kb_item(name:"Telegram/Win/Ver", value:version[1]);
        register_and_report_cpe( app:"Telegram Desktop", ver:version[1], concluded:version[0], base:"cpe:/a:telegram:tdesktop:", expr:"([0-9.]+)", insloc:location );
      }
    }
  }
}

exit(0);
