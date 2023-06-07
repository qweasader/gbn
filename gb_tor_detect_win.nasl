###############################################################################
# OpenVAS Vulnerability Test
#
# Tor Version Detection (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# Updated to detect for Beta and RC Versions
#   - By Sharath S <sharaths@secpod.com> on 2009-07-13
#
# Updated to detect version from Uninstall.exe
#   - By N Shashi Kiran N <nskiran@secpod.com> on 2011-06-16
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-07-02
# Updated to support 32 and 64 bit
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800351");
  script_version("2022-05-25T07:40:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-25 07:40:23 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Tor Version Detection (Windows)");

  script_tag(name:"summary", value:"This script detects the installed version of Tor.

  The script logs in via smb, searches for Tor in the registry
  and gets the version from registry or file.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Tor";
}

## Presently 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Tor";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

torName = registry_get_sz(key:key, item:"DisplayName");
if("Tor" >< torName)
{
  torVer = eregmatch(pattern:"Tor ([0-9.]+-?([a-z0-9]+)?)", string:torName);
  torVer = torVer[1];

  torPath = registry_get_sz(key:key, item:"UninstallString");
  torPath = str_replace(string:torPath, find:'"', replace:"");
  torPath = torPath - "Uninstall.exe";

  if(!torVer)
  {
    torVer = fetch_file_version(sysPath:torPath, file_name:"Uninstall.exe");
    if(!torVer){
      exit(0);
    }
  }

  if(torVer)
  {
    set_kb_item(name:"Tor/Win/Ver", value:torVer[1]);

    cpe = build_cpe(value: torVer, exp:"^([0-9.]+-?([a-z0-9]+)?)", base:"cpe:/a:tor:tor:");
    if(isnull(cpe))
      cpe = 'cpe:/a:tor:tor';

    register_product(cpe:cpe, location:torPath);

    log_message(data: build_detection_report(app: torName,
                                             version: torVer,
                                             install: torPath,
                                             cpe: cpe,
                                             concluded: torVer));
  }
}
