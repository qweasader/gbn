# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809767");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-12-19 15:38:50 +0530 (Mon, 19 Dec 2016)");
  script_name("Adobe Animate Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe Animate.

  The script logs in via smb, searches for 'Adobe Animate' in the registry,
  fetches install path and version information either from registry or file.");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(!registry_key_exists(key:"SOFTWARE\Adobe\Animate")){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

## Key based on architecture
if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Adobe Animate" >< appName)
  {
    appPath = registry_get_sz(key:key + item, item:"DisplayIcon");
    if(appPath)
    {
      appPath = appPath - "Setup.ico";
      appVer = fetch_file_version(sysPath:appPath, file_name:"Animate.exe");
    }
    else
    {
      appVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      appPath = "Unknown";
    }

    ## Exit if version is not available
    if(!appVer){
      exit(0);
    }

    set_kb_item(name:"Adobe/Animate/Win/Ver", value:appVer);

    cpe = build_cpe(value:appVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:animate:");
    if(isnull(cpe))
      cpe = "cpe:/a:adobe:animate";

    register_product(cpe:cpe, location:appPath);

    log_message(data: build_detection_report(app: "Adobe Animate",
                                             version: appVer,
                                             install: appPath,
                                             cpe: cpe,
                                             concluded: appVer));
    exit(0);
  }
}
exit(0);
