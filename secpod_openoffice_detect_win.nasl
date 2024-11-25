# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900072");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("OpenOffice Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  OpenOffice.

  The script logs in via smb, searches for OpenOffice in the registry and gets
  the version from 'DisplayVersion' string from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
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

if(!registry_key_exists(key:"SOFTWARE\OpenOffice.org"))
{
  if(!registry_key_exists(key:"SOFTWARE\OpenOffice"))
  {
    if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\OpenOffice.org"))
    {
      if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\OpenOffice")){
        exit(0);
      }
    }
  }
}

if("x86" >< osArch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< osArch){
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}
foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    gsName = registry_get_sz(key:key + item, item:"DisplayName");

    if("OpenOffice" >< gsName)
    {
      gsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(gsVer)
      {
        path = registry_get_sz(key:key + item , item:"InstallLocation");
        if(!path){
          path = "Could not find the install location from registry";
        }
        set_kb_item(name:"OpenOffice/Win/Ver", value:gsVer);

        cpe1 = build_cpe(value:gsVer, exp:"^([0-9.]+)", base:"cpe:/a:apache:openoffice:");
        cpe2 = build_cpe(value:gsVer, exp:"^([0-9.]+)", base:"cpe:/a:openoffice:openoffice.org:");
        if(isnull(cpe1)){
          cpe1 = "cpe:/a:apache:openoffice";
          cpe2 = "cpe:/a:openoffice:openoffice.org";
        }

        if("x64" >< osArch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"OpenOffice64/Win/Ver", value:gsVer);

          ##  Build cpe and store it as host detail
          cpe1 = build_cpe(value:gsVer, exp:"^([0-9.]+)", base:"cpe:/a:apache:openoffice:x64");
          cpe2 = build_cpe(value:gsVer, exp:"^([0-9.]+)", base:"cpe:/a:openoffice:openoffice.org:x64:");
          if(isnull(cpe1)){
            cpe1 = "cpe:/a:apache:openoffice:x64";
            cpe2 = "cpe:/a:openoffice:openoffice.org:x64";
          }
        }
        register_product(cpe:cpe1, location:path);
        register_product(cpe:cpe2, location:path);
        log_message(data: build_detection_report(app: "OpenOffice",
                                           version: gsVer,
                                           install: path,
                                           cpe: cpe1,
                                           concluded: gsVer));
      }
    }
  }
}
