# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803096");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-01-09 08:54:53 +0530 (Wed, 09 Jan 2013)");
  script_name("Microsoft System Center Operations Manager Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"Detects the installed version of Microsoft System
  Center Operations Manager.

The script logs in via smb, searches for Microsoft System Center Operations
Manager in the registry and gets the version from 'ServerVersion' string in
registry");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

scomKey = "SOFTWARE\Microsoft\Microsoft Operations Manager\";
if(!registry_key_exists(key:scomKey)){
  exit(0);
}

## Can be Updated for later versions
baseVers =  make_list("1.0", "2.0", "3.0");

foreach basever (baseVers)
{
  scom_newkey = scomKey + basever + "\Setup";
  scomName = registry_get_sz(key: scom_newkey, item:"Product");
  if(!scomName){
    continue;
  }

  if("System Center Operations Manager" >< scomName)
  {
    scomVer = registry_get_sz(key:scom_newkey, item:"ServerVersion");
    if(scomVer)
    {
      scomPath = registry_get_sz(key:scom_newkey, item:"InstallDirectory");
      if(!scomPath){
        scomPath = "Could not find the install location from registry";
      }

      scomDetails = scomName + " Server Version " + scomVer;

      set_kb_item(name:"MS/SCOM/Ver", value:scomDetails);
      set_kb_item(name:"MS/SCOM/Path", value:scomPath);

      cpe = build_cpe(value:scomVer, exp:"^([0-9.]+)",
                           base:"cpe:/a:microsoft:system_center_operations_manager:");

      if(!cpe){
        cpe = "cpe:/a:microsoft:system_center_operations_manager";
      }

      register_product(cpe:cpe, location:scomPath);

      log_message(data: build_detection_report(app: scomName,
                                              version:scomVer, install:scomPath, cpe:cpe,
                                              concluded: scomDetails));
      exit(0);
    }
  }
}
