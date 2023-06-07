# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.96019");
  script_version("2022-05-30T12:36:02+0000");
  script_tag(name:"last_modification", value:"2022-05-30 12:36:02 +0000 (Mon, 30 May 2022)");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Check over WMI if Apache is installed (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"Check over WMI if Apache is installed and report the path and
  version of the installation.");

  exit(0);
}

include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if(domain)
  usrname = domain + '\\' + usrname;

passwd = kb_smb_password();

OSVER = get_kb_item("WMI/WMI_OSVER");

if(!OSVER || OSVER >< "none") {
  set_kb_item(name:"WMI/Apache", value:"error");
  set_kb_item(name:"WMI/Apache/Version", value:"error");
  set_kb_item(name:"WMI/Apache/RootPath", value:"error");
  set_kb_item(name:"WMI/Apache/htaccessList", value:"error");
  set_kb_item(name:"WMI/Apache/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);
key = 'SOFTWARE\\Apache Software Foundation\\Apache';

if(!handle) {
  set_kb_item(name:"WMI/Apache/Version", value:"error");
  set_kb_item(name:"WMI/Apache/RootPath", value:"error");
  set_kb_item(name:"WMI/Apache/htaccessList", value:"error");
  set_kb_item(name:"WMI/Apache/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

version = wmi_reg_enum_key(wmi_handle:handlereg, key:key);

RootKey = "SOFTWARE\Apache Software Foundation\Apache\" + version;

ServerRoot = wmi_reg_get_sz(wmi_handle:handlereg, key:RootKey, key_name:"ServerRoot");

#htaccessList = wmi_query(wmi_handle:handle, query:queryht);

if(!version)
  set_kb_item(name:"WMI/Apache", value:"false");
else
  set_kb_item(name:"WMI/Apache", value:"true");

if(!version)
  version = "None";

if(!ServerRoot)
  ServerRoot = "None";

if(ServerRoot >!< "None") {
  RootPath = split(ServerRoot, sep:":", keep:FALSE);
  drive = RootPath[0] + ":";
  path = ereg_replace(pattern:"\\", replace:"\\", string:RootPath[1]);
  queryht = 'Select Name from CIM_DataFile Where Drive = "' + drive + '" AND Path LIKE "' + path + '%" AND Extension = "htaccess"';
  htaccessList = wmi_query(wmi_handle:handle, query:queryht);
  if(!htaccessList)
    htaccessList = "None";

} else {
  htaccessList = ereg_replace(pattern:'\n', replace:"|", string:htaccessList);
}

set_kb_item(name:"WMI/Apache/Version", value:version);
set_kb_item(name:"WMI/Apache/RootPath", value:ServerRoot);
set_kb_item(name:"WMI/Apache/htaccessList", value:htaccessList);

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

exit(0);
