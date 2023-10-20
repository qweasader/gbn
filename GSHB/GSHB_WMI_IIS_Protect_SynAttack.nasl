# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96027");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Tests if all Registry entries set to prevent SYN-Attacks at an IIS Server (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"Tests if all Registry entries set to prevent SYN-Attacks at an IIS Server.");

  exit(0);
}

include("http_func.inc");
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
    val ="error";
    set_kb_item(name:"WMI/IISSynAttack", value:val);
    set_kb_item(name:"WMI/IISSynAttack/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    set_kb_item(name:"WMI/TcpMaxConnectResponseRetransmissions", value:val);
    set_kb_item(name:"WMI/BacklogIncrement", value:val);
    set_kb_item(name:"WMI/MaxConnBackLog", value:val);
    set_kb_item(name:"WMI/EnableDynamicBacklog", value:val);
    set_kb_item(name:"WMI/MinimumDynamicBacklog", value:val);
    set_kb_item(name:"WMI/MaximumDynamicBacklog", value:val);
    set_kb_item(name:"WMI/DynamicBacklogGrowthDelta", value:val);
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
    val ="error";
    set_kb_item(name:"WMI/IISSynAttack", value:val);
    set_kb_item(name:"WMI/IISSynAttack/log", value:"wmi_connect: WMI Connect failed.");
    set_kb_item(name:"WMI/TcpMaxConnectResponseRetransmissions", value:val);
    set_kb_item(name:"WMI/BacklogIncrement", value:val);
    set_kb_item(name:"WMI/MaxConnBackLog", value:val);
    set_kb_item(name:"WMI/EnableDynamicBacklog", value:val);
    set_kb_item(name:"WMI/MinimumDynamicBacklog", value:val);
    set_kb_item(name:"WMI/MaximumDynamicBacklog", value:val);
    set_kb_item(name:"WMI/DynamicBacklogGrowthDelta", value:val);
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
    exit(0);
}

IISVER = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\InetStp", val_name:"MajorVersion");

if(!IISVER){
    IISSynAttackval ="None";
    set_kb_item(name:"WMI/IISSynAttack", value:IISSynAttackval);
    set_kb_item(name:"WMI/IISSynAttack/log", value:"IT-Grundschutz: IIS is not installed.");
#    set_kb_item(name:"WMI/TcpMaxConnectResponseRetransmissions", value:val);
#    set_kb_item(name:"WMI/BacklogIncrement", value:val);
#    set_kb_item(name:"WMI/MaxConnBackLog", value:val);
#    set_kb_item(name:"WMI/EnableDynamicBacklog", value:val);
#    set_kb_item(name:"WMI/MinimumDynamicBacklog", value:val);
#    set_kb_item(name:"WMI/MaximumDynamicBacklog", value:val);
#    set_kb_item(name:"WMI/DynamicBacklogGrowthDelta", value:val);
#    wmi_close(wmi_handle:handle);
#    wmi_close(wmi_handle:handlereg);
#    exit(0);
}


TCPMaxCon = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", val_name:"TcpMaxConnectResponseRetransmissions");
if (TCPMaxCon != "0")TCPMaxCon = hex2dec(xvalue:TCPMaxCon);

Backlog = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", val_name:"BacklogIncrement");
if (Backlog != "0")Backlog = hex2dec(xvalue:Backlog);

MaxCon = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", val_name:"MaxConnBackLog");
if (MaxCon != "0")MaxCon = hex2dec(xvalue:MaxCon);

EnDyn = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\AFD\Parameters", val_name:"EnableDynamicBacklog");
if (EnDyn != "0")EnDyn = hex2dec(xvalue:EnDyn);

MinDyn = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\AFD\Parameters", val_name:"MinimumDynamicBacklog");
if (MinDyn != "0")MinDyn = hex2dec(xvalue:MinDyn);

MaxDyn = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\AFD\Parameters", val_name:"MaximumDynamicBacklog");
if (MaxDyn != "0")MaxDyn = hex2dec(xvalue:MaxDyn);

DynDelta = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\AFD\Parameters", val_name:"DynamicBacklogGrowthDelta");
if (DynDelta != "0")DynDelta = hex2dec(xvalue:DynDelta);

TcpMaxPortsExhausted = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\tcpip\Parameters", val_name:"TcpMaxPortsExhausted");
if (TcpMaxPortsExhausted != "0")TcpMaxPortsExhausted = hex2dec(xvalue:TcpMaxPortsExhausted);

val = "None";

if(!TCPMaxCon) TCPMaxCon = val;
if(!Backlog) Backlog = val;
if(!MaxCon) MaxCon = val;
if(!EnDyn) EnDyn = val;
if(!MinDyn) MinDyn = val;
if(!MaxDyn) MaxDyn = val;
if(!DynDelta) DynDelta = val;
if(!TcpMaxPortsExhausted) TcpMaxPortsExhausted = val;

set_kb_item(name:"WMI/TcpMaxConnectResponseRetransmissions", value:TCPMaxCon);
set_kb_item(name:"WMI/BacklogIncrement", value:Backlog);
set_kb_item(name:"WMI/MaxConnBackLog", value:MaxCon);
set_kb_item(name:"WMI/EnableDynamicBacklog", value:EnDyn);
set_kb_item(name:"WMI/MinimumDynamicBacklog", value:MinDyn);
set_kb_item(name:"WMI/MaximumDynamicBacklog", value:MaxDyn);
set_kb_item(name:"WMI/DynamicBacklogGrowthDelta", value:DynDelta);
set_kb_item(name:"WMI/TcpMaxPortsExhausted", value:TcpMaxPortsExhausted);
if (IISSynAttackval != "None") set_kb_item(name:"WMI/IISSynAttack", value:"tested");

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

exit(0);
