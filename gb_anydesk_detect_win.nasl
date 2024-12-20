# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813553");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-06 15:50:15 +0530 (Fri, 06 Jul 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("AnyDesk Version Detection (Windows)");
  script_tag(name:"summary", value:"Detects the installed version of
  AnyDesk.

  The script logs in via smb, searches for 'AnyDesk' in the registry and gets
  the version from 'DisplayVersion' string from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk")){
    exit(0);
  }
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk" ;
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk" ;
}

adVer = registry_get_sz(item:"DisplayVersion", key:key);
adPath = registry_get_sz(item:"InstallLocation", key:key);
if(!adPath){
  adPath = "Unable to get install location from registry";
} else {
  adPath = ereg_replace(pattern:'"', string:adPath, replace:"");
}

if(adVer=~ "ad [0-9.]+"){
  version = ereg_replace(pattern:'ad ', string:adVer, replace:"");
} else if (adVer=~ "[0-9.]+"){
  version = adVer ;
}

if(version)
{
  set_kb_item(name:"AnyDesk/Win/Installed", value:TRUE);
  set_kb_item(name:"AnyDesk/Win/Ver", value:adVer);
  register_and_report_cpe(app:"AnyDesk", ver:version, base:"cpe:/a:anydesk:anydesk:", expr:"^([0-9.]+)", insloc:adPath );
}

exit(0);