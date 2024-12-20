# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802672");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-09-20 13:36:31 +0530 (Thu, 20 Sep 2012)");
  script_name("HP iNode Management Center Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"Detects the installed version of HP iNode Management Center.

  The script logs in via smb, searches for HP iNode Management Center in the
  registry and gets the version from registry key.");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
 keylist = make_list("SOFTWARE\HP\iNode Management Center\");
}

else if("x64" >< osArch)
{
  keylist =  make_list("SOFTWARE\HP\iNode Management Center\",
                       "SOFTWARE\Wow6432Node\HP\iNode Management Center\");
}

if(isnull(keylist)){
  exit(0);
}

foreach key (keylist)
{
  if(registry_key_exists(key:key))
  {
    foreach item (registry_enum_keys(key:key))
    {
      if(eregmatch(pattern:'^([0-9.]+)$', string:item))
      {
          imcVer = item;
          set_kb_item(name:"HP/iMC/Version", value:imcVer);

          newKey = "SOFTWARE\iNode\inodecenter\";
          newKeywow = "SOFTWARE\Wow6432Node\iNode\inodecenter\";

          if(registry_key_exists(key:newKey)){
              keyfound = newKey;
          }
          else if(registry_key_exists(key:newKeywow)){
              keyfound = newKeywow;
          }

          if (keyfound){
            imcPath = registry_get_sz(key: keyfound, item:"InstallDir");

            if(!imcPath || !eregmatch(pattern:"iNode Manager", string:imcPath)){
              imcPath = "Could not find the install Location from registry";
            }

            set_kb_item(name:"HP/iMC/Path", value:imcPath);
          }

          cpe = build_cpe(value:imcVer, exp:"^([0-9.]+)$", base:"cpe:/a:hp:inode_management_center_pc:");
          if(isnull(cpe))
            cpe = 'cpe:/a:hp:inode_management_center_pc';

          register_product(cpe:cpe, location:imcPath);

          log_message(data: build_detection_report(app:"HP iNode Management Center",
                                                   version: imcVer,
                                                   install: imcPath,
                                                   cpe:cpe,
                                                   concluded:imcVer));
      }
    }
    exit(0);
  }
}
