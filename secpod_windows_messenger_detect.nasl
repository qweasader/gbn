# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902915");
  script_version("2022-05-25T07:40:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-25 07:40:23 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2012-05-30 14:53:42 +0530 (Wed, 30 May 2012)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft MSN Messenger Service Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft MSN Messenger.

The script logs in via smb, searches for Microsoft MSN Messenger in the
registry and gets the exe file path from 'InstallationDirectory' string
in registry and version from the 'msmsgs.exe'");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
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

if(!registry_key_exists(key:"SOFTWARE\Microsoft\MessengerService")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\MessengerService")){
    exit(0);
  }
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\MessengerService\");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\SOFTWARE\Microsoft\MessengerService\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  path = registry_get_sz(key:key, item:"InstallationDirectory");
  if(path){
    msnVer = fetch_file_version(sysPath:path, file_name:"msmsgs.exe");
  }
  else
  {
    if("Wow6432Node" >!< key){
      msgKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
    }else{
      msgKey = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
    }

    foreach item (registry_enum_keys(key:msgKey))
    {
      apName = registry_get_sz(key:msgKey + item, item:"DisplayName");
      if("MSN Messenger" >< apName)
      {
        msnVer = registry_get_sz(key:msgKey + item, item: "DisplayVersion");
        path = "Unable to get install Path";
      }
    }
  }

  if(msnVer)
  {
    set_kb_item(name:"Microsoft/MSN/Messenger/Ver", value:msnVer);
    register_and_report_cpe( app:"Microsoft MSN Messenger Service", ver:msnVer, base:"cpe:/a:microsoft:msn_messenger:", expr:"^([0-9.]+)", insloc:path );
    exit(0);
  }
}
