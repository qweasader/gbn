# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806001");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-08-19 15:48:22 +0530 (Wed, 19 Aug 2015)");
  script_name("InduSoft Web Studio Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of
  InduSoft Web Studio.

  The script logs in via smb, searches for InduSoft Web Studio in the registry
  and gets the version from 'DisplayVersion' string from registry.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch)
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
#nb: 64 bit App is not available
else if("x64" >< os_arch)
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");

if(isnull(key_list))
  exit(0);

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key)) {
    studioName = registry_get_sz(key:key + item, item:"DisplayName");

    if(studioName && "InduSoft Web Studio" >< studioName) {

      set_kb_item(name:"schneider_indusoft/installed", value:TRUE);
      set_kb_item(name:"schneider_indusoft/smb/0/detected", value:TRUE);

      version = "unknown";

      if(studioVer = registry_get_sz(key:key + item, item:"DisplayVersion"))
        version = studioVer;

      ver = eregmatch(string:version, pattern:'([0-9]+)([0-9])([0-9.]+)');
      if(!isnull(ver[1]))
        version = ver[1] + "." + ver[2] + ver[3];

      set_kb_item(name:"schneider_indusoft/smb/0/concluded", value:studioVer);
      set_kb_item(name:"schneider_indusoft/smb/0/version", value:version);

      location = "unknown";
      studioPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(studioPath)
        location = studioPath;

      set_kb_item(name:"schneider_indusoft/smb/0/location", value:location);

      exit( 0 );
    }
  }
}

exit( 0 );
