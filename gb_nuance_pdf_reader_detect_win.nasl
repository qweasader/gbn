# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803328");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-03-11 15:20:19 +0530 (Mon, 11 Mar 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Nuance PDF Reader Version Detection (Windows)");


  script_tag(name:"summary", value:"Detects the installed version of Nuance PDF Reader on Windows.

The script logs in via smb, searches for Nuance PDF Reader in the
registry and gets the version from registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    ReaderName = registry_get_sz(key:key + item, item:"DisplayName");
    if("Nuance PDF Reader" >< ReaderName)
    {
      ReaderPath =registry_get_sz(key:key + item, item:"InstallLocation");
      if(!ReaderPath){
        ReaderPath = "Could not find the install Location";
      }

      ReaderVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(ReaderVer)
      {
        set_kb_item(name:"Nuance/PDFReader/Win/Ver", value:ReaderVer);

        cpe = build_cpe(value:ReaderVer, exp:"^([0-9.]+)", base:"cpe:/a:nuance:pdf_reader:");
        if(isnull(cpe))
          cpe = "cpe:/a:nuance:pdf_reader";

        register_product(cpe:cpe, location:ReaderPath);
        log_message(data: build_detection_report(app:"Nuance PDF Reader",
                                               version:ReaderVer,
                                               install:ReaderPath,
                                               cpe:cpe,
                                               concluded:ReaderVer));
      }
    }
  }
}
