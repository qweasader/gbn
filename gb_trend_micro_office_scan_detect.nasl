# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809140");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-08-22 15:03:13 +0530 (Mon, 22 Aug 2016)");
  script_name("Trend Micro OfficeScan Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of Trend
  Micro OfficeScan.

  The script logs in via smb, searches for string 'Trend Micro OfficeScan' in
  the registry and reads the version information from registry.");

  script_tag(name:"qod_type", value:"registry");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\TrendMicro\OfficeScan") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\TrendMicro\OfficeScan")){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(isnull(key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  trendName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Trend Micro OfficeScan" >< trendName)
  {
    trendVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    trendPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(!trendPath){
      trendPath = "Could not find the install location from registry";
    }

    if(trendVer)
    {
      set_kb_item(name:"Trend/Micro/Officescan/Ver", value:trendVer);

      cpe = build_cpe(value:trendVer, exp:"^([0-9.]+)", base:"cpe:/a:trend_micro:office_scan:");
      if(isnull(cpe))
        cpe = "cpe:/a:trend_micro:office_scan";
    }

    register_product(cpe:cpe, location:trendPath);

    log_message(data: build_detection_report(app: "Trend Micro OfficeScan",
                                             version: trendVer,
                                             install: trendPath,
                                             cpe: cpe,
                                             concluded: trendVer));
    exit(0);
  }
}
