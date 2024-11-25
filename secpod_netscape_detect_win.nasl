# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900392");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Netscape Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of Netscape.

The script logs in via smb, searches for Netscape in the registry and
gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
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

if(!registry_key_exists(key:"SOFTWARE\Netscape")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Netscape")){
    exit(0);
  }
}

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

    if("Netscape Navigator" >< appName || appName =~ "Netscape \(([0-9.]+)\)")
    {
      nsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(nsVer)
      {
        nsVer =  eregmatch(pattern:"([0-9.]+)", string:nsVer);
        if(nsVer[1]){
          nsVer = nsVer[1];
        }
      }

      if(nsVer)
      {
        appLoc = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!appLoc){
          appLoc = "Could not find the install location from registry";
        }

        set_kb_item(name:"Netscape/Win/Ver", value:nsVer);

        cpe = build_cpe(value:nsVer, exp:"^([0-9.]+)", base:"cpe:/a:netscape:navigator:");
        if(isnull(cpe))
          cpe = "cpe:/a:netscape:navigator";

        ## 64 bit apps on 64 bit platform
        if("x64" >< osArch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"Netscape64/Win/Ver", value:nsVer);

          cpe = build_cpe(value:nsVer, exp:"^([0-9.]+)", base:"cpe:/a:netscape:navigator:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:netscape:navigator:x64";
        }
        register_product(cpe:cpe, location:appLoc);
        log_message(data: build_detection_report(app: appName,
                                                 version: nsVer,
                                                 install: appLoc,
                                                 cpe: cpe,
                                                 concluded: nsVer));
      }
    }
  }
}
