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
  script_oid("1.3.6.1.4.1.25623.1.0.900959");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-10-01 12:15:29 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("freeSSHd Version Detection");


  script_tag(name:"summary", value:"Detects the installed version of freeSSHd on Windows.

The script logs in via smb, searches for freeSSHd in the registry
and extract version from the name.");

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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently freeSSHd 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  sshdName = registry_get_sz(key:key + item, item:"DisplayName");

  if("freeSSHd" >< sshdName)
  {
    sshdVer = eregmatch(pattern:"freeSSHd ([0-9.]+)", string:sshdName);

    if(!isnull(sshdVer[1]))
    {
      insLoc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insLoc){
        insLoc = "Could not find the install Location from registry";
      }

      set_kb_item(name:"freeSSHd/Ver", value:sshdVer[1]);

      cpe = build_cpe(value:sshdVer[1], exp:"^([0-9.]+)", base:"cpe:/a:freesshd:freesshd:");
      if(isnull(cpe))
        cpe = "cpe:/a:freesshd:freesshd";

      register_product(cpe:cpe, location:insLoc);

      log_message(data: build_detection_report(app: "freeSSHd",
                                               version: sshdVer[1],
                                               install: insLoc,
                                               cpe: cpe,
                                               concluded: sshdName));
    }
  }
}
