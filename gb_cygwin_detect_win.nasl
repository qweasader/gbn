# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806089");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-10-13 17:30:01 +0530 (Tue, 13 Oct 2015)");
  script_name("Cygwin Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  Cygwin on Windows.

  The script logs in via smb, searches for Cygwin in the registry and gets the
  version.");

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
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

key = "SOFTWARE\Cygwin\";
key1 ="SOFTWARE\Wow6432Node\Cygwin\";

if(!registry_key_exists(key:key))
{
  if(!registry_key_exists(key:key1)){
    exit(0);
  }
}


if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Cygwin\setup");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Cygwin\setup", "SOFTWARE\Wow6432Node\Cygwin\setup");
}

foreach key (key_list)
{
  cygPath = registry_get_sz(key:key, item:"rootdir");

  if(!cygPath){
    cygPath = "Could not find the install location from registry";
  }

  if("cygwin" >< cygPath)
  {

    ##Version info not available currently
    cygVer = "Unknown";

    set_kb_item(name:"Cygwin/Installed", value:TRUE);
    set_kb_item(name:"Cygwin/Win/Ver", value:cygVer);

    cpe = build_cpe(value:cygVer, exp:"^([0-9.]+)", base:"cpe:/a:redhat:cygwin:");
    if(isnull(cpe))
      cpe = "cpe:/a:redhat:cygwin";

    if("64" >< os_arch && "64" >< cygPath)
    {
      set_kb_item(name:"Cygwin64/Win/Ver", value:cygVer);
      cpe = build_cpe(value:cygVer, exp:"^([0-9.]+)", base:"cpe:/a:redhat:cygwin:x64:");

      if(isnull(cpe))
        cpe = "cpe:/a:redhat:cygwin:x64";
    }

    register_product(cpe:cpe, location:cygPath);
    log_message(data: build_detection_report(app: "Cygwin",
                                             version: cygVer,
                                             install: cygPath,
                                             cpe: cpe,
                                             concluded: cygVer));

  }
}
