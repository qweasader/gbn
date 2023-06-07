# Copyright (C) 2009 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900581");
  script_version("2022-05-25T07:40:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-25 07:40:23 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_name("Adobe Shockwave Player Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Adobe
  Shockwave Player on Windows.

  The script logs in via smb, searches for Adobe Shockwave Player in the
  registry, gets the version.");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!registry_key_exists(key:"SOFTWARE\Adobe"))
{
  if(!registry_key_exists(key:"SOFTWARE\Macromedia"))
  {
    if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Adobe"))
    {
      if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Macromedia")){
        exit(0);
      }
    }
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Only 32bit application is available
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  swplayerName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Shockwave" >< swplayerName)
  {
    unintPath = registry_get_sz(key:key + item, item:"UninstallString");
    break;
  }
}

if(unintPath != NULL)
{
  swPath = smb_get_systemroot();
  if(swPath == NULL){
    exit(0);
  }

  if("Adobe" >< unintPath){
    path = "Adobe";
  }
  else if("Macromed" >< unintPath){
    path = "Macromed";
  }

  if("x64" >< os_arch){
    sys = "\SysWOW64\";
  }
  else if("x86" >< os_arch){
    sys = "\System32\";
  }

  exePath = swPath + sys + path + "\Shockwave";

  swVer = fetch_file_version(sysPath: exePath, file_name: "swinit.exe");
  if(!swVer)
  {
    for(i=8; i<=12; i++)
    {
      swVer = fetch_file_version(sysPath: exePath + " " + i, file_name: "swinit.exe");
      if(swVer != NULL)
      {
        exePath = exePath + " " + i;
        break;
      }
    }
  }

  if(swVer)
  {
    set_kb_item(name:"Adobe/ShockwavePlayer/Ver", value:swVer);

    cpe = build_cpe(value: swVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:shockwave_player:");
    if(isnull(cpe))
      cpe = "cpe:/a:adobe:shockwave_player";

    register_product(cpe: cpe, location: exePath);

    log_message(data: build_detection_report(app: swplayerName,
                                             version: swVer,
                                             install: exePath,
                                             cpe: cpe,
                                             concluded: swVer));
  }
}
