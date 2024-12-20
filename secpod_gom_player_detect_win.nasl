# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903001");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-03-21 15:27:17 +0530 (Wed, 21 Mar 2012)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("GOM Media Player Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of GOM Media Player.

  The script logs in via smb, searches for GOM Media Player in the
  registry and gets the installed path from 'ProgramPath' string in registry
  and grep the version from .exe file");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\GRETECH\GomPlayer";
if(!(registry_key_exists(key:key))){
  exit(0);
}

path = registry_get_sz(key:key, item:"ProgramPath");
if(!path){
  exit(0);
}

gomVer = fetch_file_version(sysPath:path, file_name:"");
if(gomVer)
{
  set_kb_item(name:"GOM/Player/Ver/Win", value:gomVer);

  cpe = build_cpe(value:gomVer, exp:"^([0-9.]+)",
                        base:"cpe:/a:gomlab:gom_media_player:");
  if(!cpe)
    cpe="cpe:/a:gomlab:gom_media_player";
  register_product(cpe:cpe, location:path);

  log_message(data: build_detection_report(app: "GOM Media Player",
                                               version: gomVer,
                                               install: path,
                                               cpe: cpe,
                                               concluded: gomVer));
}
