# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805460");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-02 11:26:06 +0530 (Fri, 02 Jan 2015)");
  script_name("K7 Total Security Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  K7 Total Security.

  The script logs in via smb, searches for K7 Total Security in the registry
  and gets the version from 'DisplayVersion' string from registry.");

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
    k7tsecName = registry_get_sz(key:key + item, item:"DisplayName");

    if("K7TotalSecurity" >< k7tsecName) {
      k7tsecVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      k7tsecPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!k7tsecPath) {
        k7tsecPath = "Unable to find the install location from registry";
      }

      set_kb_item(name:"K7/TotalSecurity6432/Win/Installed", value:TRUE);

      if("64" >< os_arch && "Wow6432Node" >!< key) {
        set_kb_item(name:"K7/TotalSecurity64/Win/Ver", value:k7tsecVer);
        register_and_report_cpe( app:"K7 TotalSecurity", ver:k7tsecVer, base:"cpe:/a:k7computing:total_security:x64:", expr:"^([0-9.]+)", insloc:k7tsecPath );
      } else {
        set_kb_item(name:"K7/TotalSecurity/Win/Ver", value:k7tsecVer);
        register_and_report_cpe( app:"K7 TotalSecurity", ver:k7tsecVer, base:"cpe:/a:k7computing:total_security:", expr:"^([0-9.]+)", insloc:k7tsecPath );
      }
    }
  }
}
