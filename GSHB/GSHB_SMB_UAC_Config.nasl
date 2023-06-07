###############################################################################
# OpenVAS Vulnerability Test
#
# Read the config of the User Account Control feature over SMB (Windows)
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.109033");
  script_version("2022-06-15T09:34:13+0000");
  script_tag(name:"last_modification", value:"2022-06-15 09:34:13 +0000 (Wed, 15 Jun 2022)");
  script_tag(name:"creation_date", value:"2017-12-06 09:20:21 +0100 (Wed, 06 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Read the config of the User Account Control feature over SMB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB", "SMB/WindowsVersion");

  script_tag(name:"summary", value:"Read the config of the User Account Control feature over SMB from Registry");

  exit(0);
}

include("smb_nt.inc");

OSVER = get_kb_item("SMB/WindowsVersion");

if(OSVER < "6.0"){
  set_kb_item(name:"SMB/UAC", value:"error");
  set_kb_item(name:"SMB/UAC/log", value:"Can not get access to the host. Can not perform test on those systems.");
  exit(0);
}

FilterAdministratorToken = registry_get_dword(key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", item:"FilterAdministratorToken");
ConsentPromptBehaviorAdmin = registry_get_dword(key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", item:"ConsentPromptBehaviorAdmin");
ConsentPromptBehaviorUser = registry_get_dword(key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", item:"ConsentPromptBehaviorUser");
EnableInstallerDetection = registry_get_dword(key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", item:"EnableInstallerDetection");
ValidateAdminCodeSignatures = registry_get_dword(key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", item:"ValidateAdminCodeSignatures");
EnableLUA = registry_get_dword(key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", item:"EnableLUA");
PromptOnSecureDesktop = registry_get_dword(key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", item:"PromptOnSecureDesktop");
EnableVirtualization = registry_get_dword(key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", item:"EnableVirtualization");

set_kb_item(name:"SMB/UAC/FilterAdministratorToken", value:FilterAdministratorToken);
set_kb_item(name:"SMB/UAC/ConsentPromptBehaviorAdmin", value:ConsentPromptBehaviorAdmin);
set_kb_item(name:"SMB/UAC/ConsentPromptBehaviorUser", value:ConsentPromptBehaviorUser);
set_kb_item(name:"SMB/UAC/EnableInstallerDetection", value:EnableInstallerDetection);
set_kb_item(name:"SMB/UAC/ValidateAdminCodeSignatures", value:ValidateAdminCodeSignatures);
set_kb_item(name:"SMB/UAC/EnableLUA", value:EnableLUA);
set_kb_item(name:"SMB/UAC/PromptOnSecureDesktop", value:PromptOnSecureDesktop);
set_kb_item(name:"SMB/UAC/EnableVirtualization", value:EnableVirtualization);
set_kb_item(name:"SMB/UAC", value:"success");

exit(0);
