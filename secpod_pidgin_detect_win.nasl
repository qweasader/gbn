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
  script_oid("1.3.6.1.4.1.25623.1.0.900662");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Pidgin Version Detection (Windows)");

  script_tag(name:"summary", value:"This script detects the installed version of Pidgin on Windows.

The script logs in via smb, searches for Pidgin in the registry and gets the
Pidgin path and version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Pidgin\");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Pidgin\");
}

if(isnull(key_list)){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Pidgin\"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Pidgin\"))
  {
    exit(0);
  }
}

foreach key (key_list)
{
  pidginName = registry_get_sz(key:key, item:"DisplayName");

  if("Pidgin" >< pidginName)
  {
    pidginPath = registry_get_sz(key:key,item:"UninstallString");
    if(!pidginPath){
      pidginPath = "Could not find the install location from registry";
    } else {
      pidginPath = pidginPath - "pidgin-uninst.exe" ;
    }

    pidginVer = registry_get_sz(key:key, item:"DisplayVersion");
    if(pidginVer)
    {
      set_kb_item(name:"Pidgin/Win/Ver", value:pidginVer);

      cpe = build_cpe(value:pidginVer, exp:"^([0-9.]+)", base:"cpe:/a:pidgin:pidgin:");
      if(isnull(cpe))
        cpe = "cpe:/a:pidgin:pidgin";

      register_product(cpe: cpe, location: pidginPath);

      log_message(data: build_detection_report(app: "Pidgin",
                                            version: pidginVer,
                                            install: pidginPath,
                                            cpe: cpe,
                                            concluded: pidginVer));
    }
  }
}
