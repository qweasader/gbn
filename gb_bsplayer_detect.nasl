# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800268");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BS Player Free Edition Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the installed version of BS Player Free Edition.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

# Method 1
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(registry_key_exists(key:key)){

  foreach item (registry_enum_keys(key:key))
  {
    bsName = registry_get_sz(key:key + item, item:"DisplayName");
    if("BS.Player" >< bsName)
    {
      bsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(bsVer != NULL)
      {
        set_kb_item(name:"BSPlayer/Ver", value:bsVer);

        register_and_report_cpe(app:"BS Player", ver:bsVer, base:"cpe:/a:bsplayer:bs.player:",
                                expr:"^([0-9.]+)");
        exit(0);
      }
    }
  }
}

# Method 2
key2 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key2)){
    exit(0);
}

foreach item (registry_enum_keys(key:key2))
{
  bsName = registry_get_sz(key:key2 + item, item:"DisplayName");
  if("BS.Player" >< bsName || "BSPlayer" >< bsName)
  {
    path = registry_get_sz(key:key2 + item, item:"UninstallString");
    if(path != NULL)
    {
      exePath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:path);
      exePath = exePath - "uninstall.exe" + "bsplayer.exe";

      v = get_version(dllPath:exePath, string:path, offs:600000);
    }
    if(v != NULL)
    {
      set_kb_item(name:"BSPlayer/Ver", value:v);

      register_and_report_cpe(app:"BS Player", ver:v, base:"cpe:/a:bsplayer:bs.player:",
                               expr:"^([0-9.]+)");
    }
    exit(0);
  }
}
