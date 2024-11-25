# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815080");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-05-17 12:30:03 +0530 (Fri, 17 May 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Media Encoder Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe Media Encoder.

  The script logs in via smb, searches for Adobe Media Encoder in the
  registry and gets the version from 'DisplayVersion' string in registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
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
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    adName = registry_get_sz(key:key + item, item:"DisplayName");
    if("Adobe Media Encoder" >< adName)
    {
      adPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!adPath){
        adPath = "Could not find the install location from registry";
      }

      adVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(!adVer)
        adVer = "unknown";

      set_kb_item(name:"adobe/mediaencoder/win/detected", value:TRUE);

      cpe = build_cpe(value:adVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:media_encoder:");

      if(!cpe)
        cpe = "cpe:/a:adobe:media_encoder";

      if("x64" >< os_arch && "Wow6432Node" >!< key)
      {
        set_kb_item(name:"adobe/mediaencoder/x64/win", value:TRUE);

        cpe = build_cpe(value:adVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:media_encoder:x64:");
        if(!cpe)
          cpe = "cpe:/a:adobe:media_encoder:x64";
      }

      register_and_report_cpe(app:"Adobe Media Encoder", ver:adVer, concluded:"Adobe Media Encoder",
                              cpename:cpe, insloc:adPath);
      exit(0);
    }
  }
}

exit(0);
