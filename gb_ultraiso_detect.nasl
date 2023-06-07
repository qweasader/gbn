##############################################################################
# OpenVAS Vulnerability Test
#
# UltraISO Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800274");
  script_version("2022-07-06T10:11:12+0000");
  script_tag(name:"last_modification", value:"2022-07-06 10:11:12 +0000 (Wed, 06 Jul 2022)");
  script_tag(name:"creation_date", value:"2009-04-13 15:50:35 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("UltraISO Version Detection");

  script_category(ACT_GATHER_INFO);


  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version of UltraISO.");

  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "UltraISO Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ultraName = registry_get_sz(key:key + item, item:"DisplayName");
  if("UltraISO" >< ultraName)
  {
    path = registry_get_sz(key:key + item, item:"DisplayIcon");
    if(path == NULL){
       continue;
    }

    v = GetVersionFromFile(file:path, offset:1174636);

    if(v != NULL)
    {
      set_kb_item(name:"UltraISO/Ver", value:v);
      cpe = build_cpe(value:v, exp:"^([0-9.]+)", base:"cpe:/a:ezbsystems:ultraiso:");
      if(!cpe)
        cpe = "cpe:/a:ezbsystems:ultraiso";

      register_product(cpe:cpe, location:path, port:0, service:"smb-login");
      log_message(data:build_detection_report(app:"UltraISO",
                                              version:v,
                                              install:path,
                                              cpe:cpe,
                                              concluded:v));
    }
    exit(0);
  }
}
exit(0);