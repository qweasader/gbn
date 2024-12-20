# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107420");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-12-10 16:14:03 +0100 (Mon, 10 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SolarWinds TFTP Server Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version
  of SolarWinds TFTP Server for Windows.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if (!os_arch)
  exit(0);

if ("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if ("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if (isnull(key_list)) exit(0);

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key)) {

    appName = registry_get_sz(key:key + item, item:"DisplayName");
    if(!appName || appName !~ "SolarWinds TFTP Server") continue;
    version = "unknown";
    concluded = "SolarWinds TFTP Server";

    loc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!loc) continue;
    location = loc;

    vers = registry_get_sz(key:key + item, item:"DisplayVersion");
    vers_check = fetch_file_version(sysPath:location, file_name:"SolarWinds TFTP Server.exe");
    if(vers >< vers_check){
        version = vers;
      } else {
        version = "unknown"; # nb: Prevent reporting previously installed version remains.
        continue;
      }

    concluded += " " + version;

    set_kb_item(name:"solarwinds/tftp_server/win/detected", value:TRUE);
    set_kb_item(name:"solarwinds/tftp_server/win/ver", value:version);

    register_and_report_cpe(app:appName, ver:version, concluded:concluded,
    base:"cpe:/a:solarwinds:tftp_server:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0);

  }
}

exit(0);
