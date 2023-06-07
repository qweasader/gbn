####################################################################################
# OpenVAS Vulnerability Test
#
# CCleaner Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
####################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811777");
  script_version("2021-01-15T07:13:31+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"creation_date", value:"2017-09-19 11:52:53 +0530 (Tue, 19 Sep 2017)");

  script_name("CCleaner Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection CCleaner (Free and Professional Editions).");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

# nb: The Key is the same for x86 and x64 Platforms
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CCleaner";
if(!registry_key_exists(key:key))
  exit(0);

appName = registry_get_sz(key:key, item:"DisplayName");
if("CCleaner" >< appName) {

  vers = "unknown";
  path = "unknown";

  insloc = registry_get_sz(key:key, item:"InstallLocation");
  if(insloc) {
    path = insloc;

    appVer = fetch_file_version(sysPath:insloc, file_name:"CCleaner.exe");
    if(appVer) {
      set_kb_item(name:"CCleaner/Win/Ver", value:appVer);
      vers = appVer;
    }
  }

  cpe = build_cpe(value:vers, exp:"([0-9.]+)", base:"cpe:/a:piriform:ccleaner:");
  if(!cpe)
    cpe = "cpe:/a:piriform:ccleaner";

  if("x64" >< os_arch) {
    if(vers != "unknown")
      set_kb_item(name:"CCleanerx64/Win/Ver", value:vers);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:piriform:ccleaner:x64:");
    if(!cpe)
      cpe = "cpe:/a:piriform:ccleaner:x64";
  }

  # Used in gb_ccleaner_detect_portable_win.nasl to avoid doubled detections.
  # We're also stripping a possible ending backslash away as the portable NVT is getting
  # the file path without the ending backslash from WMI.
  tmp_location = tolower(path);
  tmp_location = ereg_replace(pattern:"\\$", string:tmp_location, replace:'');
  set_kb_item(name:"CCleaner/Win/InstallLocations", value:tmp_location);

  register_product(cpe:cpe, location:path, port:0, service:"smb-login");
  log_message(port:0, data:build_detection_report(app:appName, version:vers, install:path, cpe:cpe, concluded:appVer));
}

exit(0);
