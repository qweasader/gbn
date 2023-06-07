# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810216");
  script_version("2023-03-24T10:19:42+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-24 10:19:42 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2016-11-24 12:04:38 +0530 (Thu, 24 Nov 2016)");
  script_name("Avast Endpoint Protection Suite Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Avast Endpoint Protection Suite.
  The script logs in via smb, searches for string 'Avast Endpoint Protection
  Suite' in the registry and reads the version information from registry.");

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

if(!registry_key_exists(key:"SOFTWARE\AVAST Software\Avast") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\AVAST Software\Avast")){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

## Only 32-bit version is available
if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  avastName = registry_get_sz(key:key + item, item:"DisplayName");

  if(avastName =~ "avast! Endpoint Protection Suite$")
  {
    avastVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    avastPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(!avastPath){
      avastPath = "Could not find the install location from registry";
    }

    if(avastVer)
    {
      set_kb_item(name:"Avast/Endpoint-Protection-Suite/Win/Ver", value:avastVer);

      cpe = build_cpe(value:avastVer, exp:"^([0-9.]+)", base:"cpe:/a:avast:endpoint_protection_suite:");
      if(isnull(cpe))
        cpe = "cpe:/a:avast:endpoint_protection_suite";

      register_product(cpe:cpe, location:avastPath);

      log_message(data: build_detection_report(app: "Avast Endpoint Protection Suite",
                                               version: avastVer,
                                               install: avastPath,
                                               cpe: cpe,
                                               concluded: avastVer));
      exit(0);
    }
  }
}