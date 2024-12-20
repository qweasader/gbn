# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96012");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("WMI Drives Status (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"Tests WMI Drives Status.");

  exit(0);
}

include("wmi_file.inc");
include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/FS", value:"error");
  set_kb_item(name:"WMI/FDD", value:"error");
  set_kb_item(name:"WMI/CD", value:"error");
  set_kb_item(name:"WMI/USB", value:"error");
  set_kb_item(name:"WMI/BOOTINI", value:"error");
  set_kb_item(name:"WMI/BOOTDRIVE/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/FS", value:"error");
  set_kb_item(name:"WMI/FDD", value:"error");
  set_kb_item(name:"WMI/CD", value:"error");
  set_kb_item(name:"WMI/USB", value:"error");
  set_kb_item(name:"WMI/BOOTINI", value:"error");
  set_kb_item(name:"WMI/BOOTDRIVE/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

query1 = 'select DeviceID from WIN32_FloppyDrive';
query2 = 'select DeviceID from WIN32_CDROMDrive';
query3 = 'select DeviceID from WIN32_USBController';
query4 = 'select FileSystem from WIN32_LogicalDisk WHERE DriveType = 3';

WMIFDD = wmi_query(wmi_handle:handle, query:query1);
WMICD = wmi_query(wmi_handle:handle, query:query2);
WMIUSB = wmi_query(wmi_handle:handle, query:query3);
WMIFS = wmi_query(wmi_handle:handle, query:query4);
if (OSVER < 6) {
  BOOTINI = wmi_file_is_file_writeable(handle:handle, filePath:"c:\\boot.ini", includeHeader:FALSE);
  if(BOOTINI) BOOTINI = BOOTINI["c:\boot.ini"];
} else {
  BOOTINI = "No boot.ini";
}

if(!WMIFDD) WMIFDD = "None";
if(!WMICD) WMICD = "None";
if(!WMIUSB) WMIUSB = "None";
if(!WMIFS) WMIFS = "None";
if(!BOOTINI) BOOTINI = "None";

set_kb_item(name:"WMI/FS", value:WMIFS);
set_kb_item(name:"WMI/FDD", value:WMIFDD);
set_kb_item(name:"WMI/CD", value:WMICD);
set_kb_item(name:"WMI/USB", value:WMIUSB);
set_kb_item(name:"WMI/BOOTINI", value:BOOTINI);

wmi_close(wmi_handle:handle);

exit(0);
