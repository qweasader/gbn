# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.901148");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Dreamweaver Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Adobe Dreamweaver on
  Windows.

  The script logs in via smb, searches for Adobe Dreamweaver in the
  registry and gets the version from the registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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

##Registry key is different for Dreamweaver CC 2018 and Dreamweaver CC 2019
if(!registry_key_exists(key:"SOFTWARE\Adobe\Dreamweaver\") &&
  !registry_key_exists(key:"SOFTWARE\Adobe\Dreamweaver CC 2018\") &&
   !registry_key_exists(key:"SOFTWARE\Adobe\Dreamweaver CC 2019\"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Adobe\Dreamweaver\") &&
     !registry_key_exists(key:"SOFTWARE\Wow6432Node\Adobe\Dreamweaver CC 2018\")&&
     !registry_key_exists(key:"SOFTWARE\Wow6432Node\Adobe\Dreamweaver CC 2019\")){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently Gzip Wizard 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  AppName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Adobe Dreamweaver" >< AppName)
  {
    AppVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(AppVer != NULL)
    {
      appPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!appPath){
        appPath = "Could not find the install location from registry";
      }

      tmp_version = AppVer + " " +AppName;
      set_kb_item(name:"Adobe/Dreamweaver/Ver", value:tmp_version);

      cpe = build_cpe(value:AppVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:dreamweaver:");
      if(isnull(cpe))
        cpe = "cpe:/a:adobe:dreamweaver";

      register_product(cpe:cpe, location:appPath);

      log_message(data: build_detection_report(app: AppName,
                                               version: AppVer,
                                               install: appPath,
                                               cpe: cpe,
                                               concluded: tmp_version));
      exit(0);
    }
  }
}
exit(0);
