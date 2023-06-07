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
  script_oid("1.3.6.1.4.1.25623.1.0.900553");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("F-PROT Antivirus Version Detection (Windows)");


  script_tag(name:"summary", value:"Detects the installed version of F-PROT Antivirus on Windows.

The script logs in via smb, searches for F-PROT in the registry
and gets the version from the DisplayVersion string.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

key = "SOFTWARE\FRISK Software\F-PROT Antivirus for Windows";
if(!registry_key_exists(key:key))
{
  key = "SOFTWARE\Wow6432Node\FRISK Software\F-PROT Antivirus for Windows";
  if(!registry_key_exists(key:key)){
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

## F-PROT 64 bit App installs in Wow6432Node only
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  fprotName = registry_get_sz(key:key + item, item:"DisplayName");

  if("F-PROT" >< fprotName)
  {
    fprotVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(fprotVer)
    {
      insLoc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insLoc)
        insLoc = "Unable to find the install location";

      set_kb_item(name:"F-Prot/AV/Win/Installed", value:TRUE);

      if("64" >< os_arch && "x64" >< fprotName) {
        set_kb_item(name:"F-Prot64/AV/Win/Ver", value:fprotVer);
        register_and_report_cpe( app:fprotName, ver:fprotVer, concluded:fprotVer, base:"cpe:/a:f-prot:f-prot_antivirus:x64:", expr:"^([0-9.]+)", insloc:insLoc );
      } else {
        set_kb_item(name:"F-Prot/AV/Win/Ver", value:fprotVer);
        register_and_report_cpe( app:fprotName, ver:fprotVer, concluded:fprotVer, base:"cpe:/a:f-prot:f-prot_antivirus:", expr:"^([0-9.]+)", insloc:insLoc );
      }
    }
  }
}
