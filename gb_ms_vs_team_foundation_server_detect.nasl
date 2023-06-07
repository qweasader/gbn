# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802961");
  script_version("2022-12-01T10:11:22+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-12-01 10:11:22 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"creation_date", value:"2012-09-12 11:27:31 +0530 (Wed, 12 Sep 2012)");
  script_name("Microsoft Visual Studio Team Foundation / Azure DevOps Server Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"SMB login-based detection of Microsoft Visual Studio Team
  Foundation / Azure DevOps Server.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

mstfkey = "SOFTWARE\Microsoft\TeamFoundationServer\";
if(!registry_key_exists(key:mstfkey))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key))
  exit(0);

foreach item(registry_enum_keys(key:key)) {
  tfName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Microsoft Team Foundation Server" >< tfName) {
    tfNum = eregmatch(pattern:"[0-9.]+ (Update [0-9.]+)?", string:tfName);
    tfVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(tfVer) {
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insPath) {
        if(tfVer =~ "^12\.") {
          insPath = registry_get_sz(key:mstfkey + "12.0", item:"InstallPath");
        }

        else if(tfVer =~ "^14\.") {
          insPath = registry_get_sz(key:mstfkey + "14.0", item:"InstallPath");
        }

        else if(tfVer =~ "^15\.") {
          insPath = registry_get_sz(key:mstfkey + "15.0", item:"InstallPath");
        }

        else if(tfVer =~ "^16\.") {
          insPath = registry_get_sz(key:mstfkey + "16.0", item:"InstallPath");
        }

        if(!insPath)
          insPath = "Could not find the install location from registry";
      }

      set_kb_item(name:"MS/VS/Team/Foundation/Server/Ver", value:tfVer);
      set_kb_item(name:"MS/VS/Team/Foundation/Server/Path", value:insPath);

      if(tfNum[0]) {
        cpe = build_cpe(value:tfVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:visual_studio_team_foundation_server:" + tfNum[0]);
      } else {
        cpe = build_cpe(value:tfVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:visual_studio_team_foundation_server:" + tfVer);
      }

      if(!cpe)
        cpe = "cpe:/a:microsoft:visual_studio_team_foundation_server";

      register_product(cpe:cpe, location:insPath, port:0, service:"smb-login");

      log_message(data:build_detection_report(app:"Microsoft Visual Studio Team Foundation Server",
                                              version:tfVer,
                                              install:insPath,
                                              cpe:cpe,
                                              concluded:tfVer));
    }
  }

  ## For latest TFS == AzureDevOps Server 2019
  if("AzureDevOpsCore2019" >< tfName || "AzureDevOpsCore2020" >< tfName) {
    tfVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(tfVer) {
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insPath) {
        if(tfVer =~ "^17\.") {
          insPath = registry_get_sz(key:mstfkey + "17.0", item:"InstallPath");
          if(!insPath)
            insPath = "Could not find the install location from registry";
        }

        else if(tfVer =~ "^18\.") {
          insPath = registry_get_sz(key:mstfkey + "18.0", item:"InstallPath");
          if(!insPath)
            insPath = "Could not find the install location from registry";
        }
      }

      set_kb_item(name:"MS/Azure/DevOps/Server/Ver", value:tfVer);
      set_kb_item(name:"MS/Azure/DevOps/Server/Path", value:insPath);

      cpe = build_cpe(value:tfVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:azure_devops_server:" + tfVer);
      if(!cpe)
        cpe = "cpe:/a:microsoft:azure_devops_server";

      register_product(cpe:cpe, location:insPath, port:0, service:"smb-login");

      log_message(data:build_detection_report(app:"Microsoft Azure DevOps Server",
                                              version:tfVer,
                                              install:insPath,
                                              cpe:cpe,
                                              concluded:tfVer));
      exit(0);
    }
  }
}

exit(0);
