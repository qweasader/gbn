# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107320");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2018-04-24 11:23:58 +0200 (Tue, 24 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Adobe Flash Player Portable Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_wmi_access.nasl", "lsc_options.nasl");
  script_mandatory_keys("win/lsc/search_portable_apps", "WMI/access_successful");
  script_exclude_keys("win/lsc/disable_wmi_search");

  script_tag(name:"summary", value:"SMB login and WMI file search based detection of the portable
  Adobe Flash Player variant.");

  script_tag(name:"insight", value:"To enable the search for portable versions of this product you
  need to 'Enable Detection of Portable Apps on Windows' in the 'Options for Local Security Checks'
  (OID: 1.3.6.1.4.1.25623.1.0.100509) of your scan config.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("wmi_file.inc");
include("list_array_func.inc");
include("misc_func.inc");
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

query = "SELECT Name FROM CIM_DataFile WHERE NOT Path LIKE '%\\windows\\install%' AND FileName LIKE 'NPSWF%' AND Extension = 'dll'";
fileList = wmi_query( wmi_handle:handle, query:query );
if( "NTSTATUS" >< fileList || ! fileList ) {
  wmi_close( wmi_handle:handle );
  exit( 0 );
}

# From the other flash detection VTs to avoid a doubled detection of a registry-based installation.
detectedList = get_kb_list( "AdobeFlashPlayer/Win/InstallLocations" );

fileList = split( fileList, keep:FALSE );

foreach filePath( fileList ) {

  if( filePath == "Name" ) continue; # Just ignore the header of the list...

  # The WMI query returns filenames like npswf32_29_0_0_140.dll so we're stripping it away
  # to keep the install location registration the same way like in other flash detection VTs.
  location = ereg_replace( string:filePath, pattern:"\\npswf.*\.dll", replace:"" );

  if( detectedList && in_array( search:tolower( location ), array:detectedList ) ) continue; # We already have detected this installation...

  # nb: wmi_file_fileversion needs doubled backslash in the path but
  # the query above returns single backslash in the path...
  filePath = ereg_replace( pattern:"\\", replace:"\\", string:filePath );

  versList = wmi_file_fileversion( handle:handle, filePath:filePath, includeHeader:FALSE );
  if( ! versList || ! is_array( versList ) ) continue;
  foreach vers( keys( versList ) ) {

    # Version of the .dll contains something like 29.0.0.140 or 30.0.0.113
    if( versList[vers] && version = eregmatch( string:versList[vers], pattern:"^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)" ) ) {

      set_kb_item( name:"adobe/flash_player/detected", value:TRUE );
      set_kb_item( name:"AdobeFlashPlayer/Win/InstallLocations", value:tolower( location ) );
      set_kb_item( name:"AdobeFlashPlayer/Win/Installed", value:TRUE );

      if( "system32" >< location ) {
        base = "cpe:/a:adobe:flash_player:x64:";
        app  = "Adobe Flash Player Plugin 64bit";
      } else if( "syswow64" >< location ) {
        base = "cpe:/a:adobe:flash_player:";
        app  = "Adobe Flash Player Plugin 32bit";
      } else if( "npsfw64" >< filePath ) { # nb: location doesn't contain the filename...
        base = "cpe:/a:adobe:flash_player:x64:";
        app = "Adobe Flash Player Plugin 64bit Portable";
      } else {
        base = "cpe:/a:adobe:flash_player:";
        app = "Adobe Flash Player Plugin 32bit Portable";
      }
      register_and_report_cpe( app:app, ver:version[1], concluded:versList[vers], base:base, expr:"^([0-9.]+)", insloc:location, regPort:0, regService:"smb-login" );
    }
  }
}

wmi_close( wmi_handle:handle );
exit( 0 );
