# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96029");
  script_version("2024-02-22T14:37:29+0000");
  script_tag(name:"last_modification", value:"2024-02-22 14:37:29 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Test over WMI, if Microsoft IIS installed and list open ports - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "secpod_open_tcp_ports.nasl");

  script_tag(name:"summary", value:"Test over WMI, if Microsoft IIS installed and list open ports.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("port_service_func.inc");
include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

ports = tcp_get_all_ports();
OSVER = get_kb_item("WMI/WMI_OSVER");

if(!OSVER || "none" >< OSVER){
  set_kb_item(name:"WMI/IISandPorts", value:"error");
  set_kb_item(name:"WMI/IISandPorts/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/IISandPorts", value:"error");
  set_kb_item(name:"WMI/IISandPorts/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

IISVER = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\\Microsoft\\InetStp", val_name:"MajorVersion");

if(!IISVER){
    set_kb_item(name:"WMI/IISandPorts", value:"None");
    set_kb_item(name:"WMI/IISandPorts/log", value:"IT-Grundschutz: IIS is not installed");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
    exit(0);
}

if(isnull(ports)){
    set_kb_item(name:"WMI/IISandPorts", value:"error");
    set_kb_item(name:"WMI/IISandPorts/log", value:"IT-Grundschutz: Not Ports detected, perhaps Port Scanner was not applied!");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
exit(0);
}

portlist = "IIS Version " + IISVER + '|';

foreach port( ports ) {
  portlist = portlist + port + '|';
}

set_kb_item(name:"WMI/IISandPorts", value:portlist);
wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);
exit(0);
