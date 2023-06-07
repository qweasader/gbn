# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809190");
  script_version("2023-03-24T10:19:42+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-24 10:19:42 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2016-09-02 14:36:53 +0530 (Fri, 02 Sep 2016)");
  script_name("HPE Insight Management Sizer Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  HPE Insight Management Sizer.

  The script logs in via smb, searches for 'HPE Insight Management Sizing
  Tool' in the registry, gets version and installation path
  information from the registry.");

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

if(!registry_key_exists(key:"SOFTWARE\Hewlett Packard Enterprise\Sizers\HPE Insight Management Sizing Tool") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Hewlett Packard Enterprise\Sizers\HPE Insight Management Sizing Tool")){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

##Key based on architecture
if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  hpName = registry_get_sz(key:key + item, item:"DisplayName");

  if("HPE Insight Management Sizing Tool" >< hpName)
  {
    hpVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(hpVer)
    {
      hpPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!hpPath){
        hpPath = "Could not find the install location from registry";
      }

      set_kb_item(name:"HPE/Insight/Management/Win/Ver", value:hpVer);

      cpe = build_cpe(value:hpVer, exp:"^([0-9.]+)", base:"cpe:/a:hp:insight_management_sizer:");
      if(isnull(cpe))
        cpe = "cpe:/a:hp:insight_management_sizer";

      register_product(cpe:cpe, location:hpPath);

      log_message(data: build_detection_report(app: "HPE Insight Management Sizer",
                                               version: hpVer,
                                               install: hpPath,
                                               cpe: cpe,
                                               concluded: hpVer));
    }
  }
}