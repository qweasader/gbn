# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805711");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-03 11:19:11 +0530 (Fri, 03 Jul 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Cisco Jabber Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  Cisco Jabber.

  The script logs in via smb, searches for Cisco Jabber in the registry
  and gets the version from 'DisplayVersion' string from registry.");

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

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    jbName = registry_get_sz(key:key + item, item:"DisplayName");

    if("Cisco Jabber" >< jbName)
    {
      jbVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      jbPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!jbPath){
        jbPath = "Unable to find the install location from registry";
      }

      if(jbVer)
      {
        set_kb_item(name:"Cisco/Jabber/Win/Ver", value:jbVer);

        cpe = build_cpe(value:jbVer, exp:"^([0-9.]+)", base:"cpe:/a:cisco:jabber:");
        if(isnull(cpe))
          cpe = "cpe:/a:cisco:jabber";

        ## 64 bit apps on 64 bit platform
        if("x64" >< os_arch && "x86" >!< jbPath)
        {
          set_kb_item(name:"Cisco/Jabber64/Win/Ver", value:jbVer);

          cpe = build_cpe(value:jbVer, exp:"^([0-9.]+)", base:"cpe:/a:cisco:jabber:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:cisco:jabber:x64";
        }

       register_product(cpe:cpe, location:jbPath);
       log_message(data: build_detection_report(app: "Cisco Jabber",
                                                version: jbVer,
                                                install: jbPath,
                                                cpe: cpe,
                                                concluded: jbVer));
      }
    }
  }
}
