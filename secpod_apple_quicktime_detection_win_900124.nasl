# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900124");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple QuickTime Version Detection for Windows");

  script_tag(name:"summary", value:"Detects the installed version of Apple QuickTime.

The script logs in via smb, searches for executable of Apple QuickTime
'QuickTimePlayer.exe' and gets the file version.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Apple Computer, Inc.\QuickTime";
}

## 64 bit app is not available
## so checking for 32 bit app on 64 bit.
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Apple Computer, Inc.\QuickTime";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

quickTimePath = registry_get_sz(item:"InstallDir", key:key);
if(!quickTimePath){
  exit(0);
}

quickTimeVer = fetch_file_version(sysPath:quickTimePath,
                                  file_name: "\QuickTimePlayer.exe");
if(quickTimeVer)
{
  set_kb_item(name:"QuickTime/Win/Ver", value:quickTimeVer);

  cpe = build_cpe(value:quickTimeVer, exp:"^([0-9.]+)", base:"cpe:/a:apple:quicktime:");
  if(isnull(cpe))
    cpe = "cpe:/a:apple:quicktime";

  register_product(cpe:cpe, location:quickTimePath);
  log_message(data: build_detection_report(app:"Apple QuickTime",
                                           version:quickTimeVer,
                                           install:quickTimePath,
                                           cpe:cpe,
                                           concluded:quickTimeVer));
}
