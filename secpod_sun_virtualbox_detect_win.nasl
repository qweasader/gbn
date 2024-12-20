# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901053");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_name("Sun VirtualBox Detection (Windows SMB Login)");
  script_tag(name:"summary", value:"Detects the installed version of Sun/Oracle VirtualBox.

  The script logs in via smb, searches for Sun/Oracle VirtualBox in the registry
  and gets the version from 'Version' string in registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Function to build cpe
function building_cpe(version, insPath)
{
  set_kb_item(name:"Oracle/VirtualBox/Win/Ver", value:version);
  set_kb_item(name:"VirtualBox/Win/installed", value: TRUE);
  if(version_is_less(version:version, test_version:"3.2.0"))
  {
    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:sun:virtualbox:");
    if(!(cpe))
      cpe="cpe:/a:sun:virtualbox";

    if(cpe)
      register_product(cpe:cpe, location:insPath);

      log_message(data: build_detection_report(app:"Sun/Oracle VirtualBox",
                                           version:version,
                                           install: insPath,
                                           cpe:cpe,
                                           concluded:version));
  }
  else
  {
    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:oracle:vm_virtualbox:");
    if(!(cpe))
      cpe="cpe:/a:oracle:vm_virtualbox";

    if(cpe)
      register_product(cpe:cpe, location:insPath);

      log_message(data: build_detection_report(app:"Sun/Oracle VirtualBox",
                                           version:version,
                                           install: insPath,
                                           cpe:cpe,
                                           concluded:version));
  }
}

checkdupvmVer = ""; # nb: To make openvas-nasl-lint happy...

if(!registry_key_exists(key:"SOFTWARE\Sun\VirtualBox") &&
   !registry_key_exists(key:"SOFTWARE\Sun\xVM VirtualBox") &&
   !registry_key_exists(key:"SOFTWARE\Oracle\VirtualBox")){
  exit(0);
}

vmVer = registry_get_sz(key:"SOFTWARE\Oracle\VirtualBox", item:"version");

if(vmVer && egrep(string:vmVer, pattern:"^([0-9.]+)"))
{
  if (vmVer + ", " >< checkdupvmVer){
    continue;
  }

  checkdupvmVer += vmVer + ", ";

  inPath = registry_get_sz(key:"SOFTWARE\Oracle\VirtualBox",  item:"InstallDir");
  if(!inPath){
    inPath = "Could not find the install location from registry";
  }

  building_cpe(version:vmVer, insPath:inPath);
}

path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach item (registry_enum_keys(key:path))
{
  vbname = registry_get_sz(key:path + item, item:"DisplayName");

  if("Sun VirtualBox" >< vbname || "Oracle VM VirtualBox" >< vbname)
  {
    vmVer = registry_get_sz(key:path + item, item:"DisplayVersion");

    if(vmVer && egrep(string:vmVer, pattern:"^([0-9.]+)"))
    {
      if (vmVer + ", " >< checkdupvmVer){
        continue;
      }

      checkdupvmVer += vmVer + ", ";

      inPath = registry_get_sz(key:path + item,  item:"InstallLocation");
      if(!inPath){
        inPath = "Could not find the install Location from registry";
      }

      building_cpe(version:vmVer, insPath:inPath);
    }
  }

  else if("Sun xVM VirtualBox" >< vbname || "Oracle xVM VirtualBox" >< vbname)
  {
    xvmVer = registry_get_sz(key:path + item, item:"DisplayVersion");

    if(xvmVer && egrep(string:xvmVer, pattern:"^([0-9.]+)"))
    {
      set_kb_item(name:"Sun/xVM-VirtualBox/Win/Ver", value:xvmVer);
      set_kb_item(name:"VirtualBox/Win/installed", value: TRUE);

     inPath = registry_get_sz(key:path + item,  item:"InstallLocation");
      if(!inPath){
        inPath = "Could not find the install location from registry";
      }

     cpe = build_cpe(value:xvmVer, exp:"^([0-9.]+)", base:"cpe:/a:sun:xvm_virtualbox:");
     if(!(cpe))
       cpe="cpe:/a:sun:xvm_virtualbox:";
     if(cpe)
       register_product(cpe:cpe, location:inPath);

       log_message(data: build_detection_report(app:"Sun/Oracle xVirtualBox ",
                                              version:xvmVer,
                                              install: inPath,
                                              cpe:cpe,
                                              concluded:xvmVer));

    }
  }
}
