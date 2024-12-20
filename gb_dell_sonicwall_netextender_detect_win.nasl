# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806042");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-08 13:38:49 +0530 (Tue, 08 Sep 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Dell SonicWall NetExtender Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  Dell SonicWall NetExtender on Windows.

  The script logs in via smb, searches for 'Dell SonicWall NetExtender' in the
  registry and gets the version from 'DisplayVersion' string from
  registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## 64 bit App is not available
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(isnull(key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  netextName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Dell SonicWALL NetExtender" >< netextName)
  {
    netextVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    netextPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(!netextPath){
      netextPath = "Unable to find the install location from registry";
    }

    if(netextVer){
      set_kb_item(name:"Dell/SonicWall/NetExtender/Win/Ver", value:netextVer);
      register_and_report_cpe( app:"Dell SonicWall NetExtender", ver:netextVer, base:"cpe:/a:sonicwall:netextender:", expr:"^([0-9.]+)", insloc:netextPath );
    }
  }
}
