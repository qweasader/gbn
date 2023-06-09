###############################################################################
# OpenVAS Vulnerability Test
#
# Get EFS Encrypted Files, Dirs and EFS-Encryption AlgorithmID (win)
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96043");
  script_version("2022-06-15T09:34:13+0000");
  script_tag(name:"last_modification", value:"2022-06-15 09:34:13 +0000 (Wed, 15 Jun 2022)");
  script_tag(name:"creation_date", value:"2010-01-13 14:14:12 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Get EFS Encrypted Files, Dirs and EFS-Encryption AlgorithmID (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"GGet EFS Encrypted Files, Dirs and EFS-Encryption AlgorithmID (win)");

  exit(0);
}

include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

OSVER = get_kb_item("WMI/WMI_OSVER");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/WMI_EncrFile", value:"error");
  set_kb_item(name:"WMI/WMI_EncrDir", value:"error");
  set_kb_item(name:"WMI/WMI_EFSAlgorithmID", value:"error");
  set_kb_item(name:"WMI/WMI_EFS/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle || !handlereg){
  set_kb_item(name:"WMI/WMI_EncrFile", value:"error");
  set_kb_item(name:"WMI/WMI_EncrDir", value:"error");
  set_kb_item(name:"WMI/WMI_EFSAlgorithmID", value:"error");
  set_kb_item(name:"WMI/WMI_EFS/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}


query1 = 'select Name from CIM_DataFile WHERE Encrypted = True';
query2 = 'select Name from Win32_Directory WHERE Encrypted = True';
EFSAlgorithmID = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS", val_name:"AlgorithmID");
EncrFile = wmi_query(wmi_handle:handle, query:query1);
EncrDir = wmi_query(wmi_handle:handle, query:query2);


if (!EncrFile) EncrFile = "none";
if (!EncrDir) EncrDir = "none";
if (!EFSAlgorithmID) EFSAlgorithmID = "none";

set_kb_item(name:"WMI/WMI_EncrFile", value:EncrFile);
set_kb_item(name:"WMI/WMI_EncrDir", value:EncrDir);
set_kb_item(name:"WMI/WMI_EFSAlgorithmID", value:EFSAlgorithmID);

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

exit(0);
