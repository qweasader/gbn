# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803770");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-10-17 15:40:00 +0530 (Thu, 17 Oct 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe RoboHelp Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Adobe RoboHelp on Windows.

The script logs in via smb, searches for Adobe RoboHelp in the registry
and gets the version from registry.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(!registry_key_exists(key:"SOFTWARE\Adobe\RoboHelp"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Adobe\RoboHelp")){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently Adobe RoboHelp 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  arhName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Adobe RoboHelp" >< arhName)
  {
    arhInsPath = registry_get_sz(key:key + item, item:"DisplayIcon");
    if(arhInsPath){
      arhInsPath = arhInsPath - "\ARPRobohelp.ico";
    } else {
      arhInsPath = "Could not find the install location from registry";
    }

    arhVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(arhVer) {
      if("Server" >< arhName) {
        set_kb_item(name:"Adobe/RoboHelp/Server/Win/Ver", value: arhVer);
        register_and_report_cpe( app:arhName, ver:arhVer, concluded:arhVer, base:"cpe:/a:adobe:robohelp_server:", expr:"^([0-9.]+)", insloc:arhInsPath );
      } else {
        set_kb_item(name:"Adobe/RoboHelp/Win/Ver", value: arhVer);
        set_kb_item(name:"Adobe/RoboHelp/Win/InstallPath", value: arhInsPath);
        register_and_report_cpe( app:arhName, ver:arhVer, concluded:arhVer, base:"cpe:/a:adobe:robohelp:", expr:"^([0-9.]+)", insloc:arhInsPath );
      }
    }
  }
}
