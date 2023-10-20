# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805288");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-02-23 13:21:29 +0530 (Mon, 23 Feb 2015)");
  script_name("BullGuard Backup Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  BullGuard Backup.

  The script logs in via smb, searches for 'BullGuard Backup' in the registry,
  gets installation path from the registry and then reads version information
  from 'version.txt' text file.");

  script_tag(name:"qod_type", value:"registry");

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

if(!registry_key_exists(key:"SOFTWARE\BullGuard Ltd.")){
  exit(0);
}

## Key is same for 32 bit and 64 bit platform for bullguard
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BullGuard";
if(!registry_key_exists(key:key)){
  exit(0);
}

bgName = registry_get_sz(key:key, item:"DisplayName");

if("BullGuard Backup" >< bgName)
{
  bgPath = registry_get_sz(key:key, item:"InstallLocation");

  if(bgPath)
  {
    bgfile = bgPath + "\version.txt";
    txtRead = smb_read_file(fullpath:bgfile, offset:0, count:50);

    bgVer = eregmatch(pattern:"^([0-9.]+)", string:txtRead);
    bgVer = bgVer[1];

    if(bgVer)
    {
      set_kb_item(name:"BullGuard/Backup/Ver", value:bgVer);

      cpe = build_cpe(value:bgVer, exp:"^([0-9.]+)", base:"cpe:/a:bullguard:online_backup:");
      if(isnull(cpe))
        cpe = 'cpe:/a:bullguard:online_backup';

      if("64" >< os_arch)
      {
        set_kb_item(name:"BullGuard/Backup64/Ver", value:bgVer);

        cpe = build_cpe(value:bgVer, exp:"^([0-9.]+)", base:"cpe:/a:bullguard:online_backup:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:bullguard:online_backup:x64";
      }

      register_product(cpe:cpe, location:bgPath);
      log_message(data: build_detection_report(app: bgName,
                                             version: bgVer,
                                             install: bgPath,
                                             cpe: cpe,
                                             concluded: bgVer));
    }
  }
}
