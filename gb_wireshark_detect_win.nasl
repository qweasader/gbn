###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Version Detection (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800038");
  script_version("2022-05-31T20:54:22+0100");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-31 20:54:22 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Wireshark Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Wireshark on Windows.

The script logs in via smb, searches for Wireshark in the registry
and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## For 64 bit app also key is creating under Wow6432Node
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

wireName = registry_get_sz(key: key + "Wireshark", item:"DisplayName");

if("Wireshark" >< wireName)
{
  wiresharkVer = registry_get_sz(key: key + "Wireshark", item:"DisplayVersion");

  path = registry_get_sz(key: key + "Wireshark", item:"UninstallString");
  if(path){
    path = path - "\uninstall.exe";
  } else {
    path = "Unable to find the install location from registry.";
  }

  if(wiresharkVer)
  {
    set_kb_item(name:"Wireshark/Win/Ver", value:wiresharkVer);

    cpe = build_cpe(value:wiresharkVer, exp:"^([0-9.]+)", base:"cpe:/a:wireshark:wireshark:");
    if(isnull(cpe))
      cpe = 'cpe:/a:wireshark:wireshark';

    if("64" >< os_arch && "64-bit" >< wireName)
    {
      set_kb_item(name:"Wireshark64/Win/Ver", value:wiresharkVer);

      cpe = build_cpe(value:wiresharkVer, exp:"^([0-9.]+)", base:"cpe:/a:wireshark:wireshark:x64:");
      if(isnull(cpe))
        cpe = 'cpe:/a:wireshark:wireshark:x64';
    }

    register_product(cpe:cpe, location:path);

    log_message(data: build_detection_report(app: wireName,
                                             version: wiresharkVer,
                                             install: path,
                                             cpe: cpe,
                                             concluded: wiresharkVer));
  }
}
