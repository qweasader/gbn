# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803872");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-08-21 12:41:35 +0530 (Wed, 21 Aug 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_name("WinSCP Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of WinSCP.

The script logs in via smb, searches for WinSCP in the registry, gets
version from the 'DisplayVersion' string and set it in the KB item.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

## Presently 64bit application is not available
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if(appName =~ "^WinSCP")
  {
    insloc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!insloc){
      insloc = "Could not find the install location from registry";
    }

    scpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(scpVer != NULL)
    {
      set_kb_item(name:"WinSCP/Win/Ver", value:scpVer);

      cpe = build_cpe(value:scpVer, exp:"^([0-9.]+)( beta|RC)?", base:"cpe:/a:winscp:winscp:");
      if(isnull(cpe))
        cpe = "cpe:/a:winscp:winscp";

      register_product(cpe:cpe, location:insloc);

      log_message(data: build_detection_report(app: appName,
                                               version: scpVer,
                                               install: insloc,
                                               cpe: cpe,
                                               concluded: scpVer));
    }
  }
}
