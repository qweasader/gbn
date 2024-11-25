# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901144");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_tag(name:"qod_type", value:"registry");
  script_name("FreeType Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of FreeType.

The script logs in via smb, searches for FreeType in the registry and
gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
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

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\GnuWin32\FreeType") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\GnuWin32\FreeType"))
{
  exit(0);
}

## if os is 32 bit iterate over common path
if("x86" >< osArch){
  key_list = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch){
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    appName = registry_get_sz(key:key + item, item:"DisplayName");

    if("FreeType" >< appName)
    {
      ftVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(ftVer)
      {
        appLoc = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!appLoc){
          appLoc = "Could not find the install location from registry";
        }

        set_kb_item(name:"FreeType/Win/Ver", value:ftVer);

        base = "cpe:/a:freetype:freetype:";

        ## 64 bit apps on 64 bit platform
        if("x64" >< osArch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"FreeType64/Win/Ver", value:ftVer);

          base = "cpe:/a:freetype:freetype:x64:";
        }
        register_and_report_cpe( app: appName,
                                 ver: ftVer,
                                 concluded: ftVer,
                                 base: base,
                                 expr: "^([0-9.]+)",
                                 insloc: appLoc );
      }
    }
  }
}
