# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96017");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Get Windows Firewall Profile Status over WMI (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("toolcheck.nasl", "smb_login.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"Get Windows Firewall Profile Status over WMI.
  In this Test is currently only an Registry Test for the Microsoft Firewall
  realized.

  Later we will test over WMI the Namespace SecurityCenter\FirewallProduct and
  SecurityCenter2\FirewallProduct for third party Firewall Products. The WMI
  test can only used for Microsoft Client and not for Server Systems.");

  exit(0);
}

include("wmi_svc.inc");
include("wmi_os.inc");
include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();



OSVER = get_kb_item("WMI/WMI_OSVER");
FWOSVER = OSVER;
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
SMBOSVER = get_kb_item("SMB/WindowsVersion");

if((!OSVER || OSVER >< "none") && !SMBOSVER){
    set_kb_item(name:"WMI/WinFirewall", value:"error");
    set_kb_item(name:"WMI/WinFirewall/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/WinFirewall", value:"error");
  set_kb_item(name:"WMI/WinFirewall/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

if ((!OSVER || OSVER == "none") && SMBOSVER) OSVER = SMBOSVER;

if (OSVER < '5.1'){
    set_kb_item(name:"WMI/WinFirewall", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/IPFilter", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/STD", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/DOM", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/PUB", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/Firewall_Name", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/Firewall_State", value:"inapplicable");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
    exit(0);
}

if (OSVER == '5.1' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition'){
  if(FWOSVER == "none"){
    set_kb_item(name:"WMI/WinFirewall", value:"on");
    set_kb_item(name:"WMI/WinFirewall/IPFilter", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/STD", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/DOM", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/PUB", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/Firewall_Name", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/Firewall_State", value:"inapplicable");
    exit(0);
  }
  else{
 FirewallDOM = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", val_name:"EnableFirewall");

 FirewallPUB = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", val_name:"EnableFirewall");

 FirewallSTD = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", val_name:"EnableFirewall");


# FirewallSTD = "inapplicable";
 if(!FirewallSTD) FirewallSTD = "off";
 if(!FirewallDOM) FirewallDOM = "off";
 if(!FirewallPUB) FirewallPUB = "off";
 set_kb_item(name:"WMI/WinFirewall", value:"inapplicable");
 set_kb_item(name:"WMI/WinFirewall/IPFilter", value:"inapplicable");
 set_kb_item(name:"WMI/WinFirewall/STD", value:FirewallSTD);
 set_kb_item(name:"WMI/WinFirewall/DOM", value:FirewallDOM);
 set_kb_item(name:"WMI/WinFirewall/PUB", value:FirewallPUB);
 set_kb_item(name:"WMI/WinFirewall/Firewall_Name", value:"inapplicable");
 set_kb_item(name:"WMI/WinFirewall/Firewall_State", value:"inapplicable");
 wmi_close(wmi_handle:handle);
 wmi_close(wmi_handle:handlereg);
 exit(0);
 }
}

if (OSVER == '5.2' && OSNAME >!< 'Microsoft(R) Windows(R) XP Professional x64 Edition'){

  if(FWOSVER == "none"){
    set_kb_item(name:"WMI/WinFirewall", value:"on");
    set_kb_item(name:"WMI/WinFirewall/IPFilter", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/STD", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/DOM", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/PUB", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/Firewall_Name", value:"inapplicable");
    set_kb_item(name:"WMI/WinFirewall/Firewall_State", value:"inapplicable");
    exit(0);
  }
  else{
      IPFilterquery = 'select Caption, IPFilterSecurityEnabled from Win32_NetworkAdapterConfiguration WHERE IPFilterSecurityEnabled = False OR IPFilterSecurityEnabled = True';
      IPFilter = wmi_query(wmi_handle:handle, query:IPFilterquery);
      if(!IPFilter) IPFilter = "None";
      set_kb_item(name:"WMI/WinFirewall", value:"inapplicable");
      set_kb_item(name:"WMI/WinFirewall/IPFilter", value:IPFilter);
      set_kb_item(name:"WMI/WinFirewall/STD", value:"inapplicable");
      set_kb_item(name:"WMI/WinFirewall/DOM", value:"inapplicable");
      set_kb_item(name:"WMI/WinFirewall/PUB", value:"inapplicable");
      set_kb_item(name:"WMI/WinFirewall/Firewall_Name", value:"inapplicable");
      set_kb_item(name:"WMI/WinFirewall/Firewall_State", value:"inapplicable");
      wmi_close(wmi_handle:handle);
      wmi_close(wmi_handle:handlereg);
      exit(0);
    }
}



if(FWOSVER == "none"){
  set_kb_item(name:"WMI/WinFirewall", value:"on");
  set_kb_item(name:"WMI/WinFirewall/IPFilter", value:"inapplicable");
  set_kb_item(name:"WMI/WinFirewall/STD", value:"inapplicable");
  set_kb_item(name:"WMI/WinFirewall/DOM", value:"inapplicable");
  set_kb_item(name:"WMI/WinFirewall/PUB", value:"inapplicable");
  set_kb_item(name:"WMI/WinFirewall/Firewall_Name", value:"inapplicable");
  set_kb_item(name:"WMI/WinFirewall/Firewall_State", value:"inapplicable");
  exit(0);
}

if (OSVER >= '6.0'){
  FirewallSTD = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", val_name:"EnableFirewall");
}else FirewallSTD = "inapplicable";

FirewallDOM = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", val_name:"EnableFirewall");

FirewallPUB = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", val_name:"EnableFirewall");

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

if(!FirewallSTD) FirewallSTD = "off";
if(!FirewallDOM) FirewallDOM = "off";
if(!FirewallPUB) FirewallPUB = "off";

set_kb_item(name:"WMI/WinFirewall/STD", value:FirewallSTD);
set_kb_item(name:"WMI/WinFirewall/DOM", value:FirewallDOM);
set_kb_item(name:"WMI/WinFirewall/PUB", value:FirewallPUB);
set_kb_item(name:"WMI/WinFirewall", value:"inapplicable");
set_kb_item(name:"WMI/WinFirewall/IPFilter", value:"inapplicable");
if (OSTYPE != 1){
  set_kb_item(name:"WMI/WinFirewall/Firewall_Name", value:"inapplicable");
  set_kb_item(name:"WMI/WinFirewall/Firewall_State", value:"inapplicable");
}

if (OSVER >= '6.0' && OSTYPE == 1){
  ns = 'root\\SecurityCenter2';
  fwquery1 = 'select displayName from FirewallProduct';
  fwquery2 = 'select productState from FirewallProduct';

  handlefw = wmi_connect(host:host, username:usrname, password:passwd, ns:ns);

  Firewall_Name = wmi_query(wmi_handle:handlefw, query:fwquery1);
  Firewall_State = wmi_query(wmi_handle:handlefw, query:fwquery2);

  if(!Firewall_Name) Firewall_Name = "none";
  if(!Firewall_State) Firewall_State = "none";

  set_kb_item(name:"WMI/WinFirewall/Firewall_Name", value:Firewall_Name);
  set_kb_item(name:"WMI/WinFirewall/Firewall_State", value:Firewall_State);

  wmi_close(wmi_handle:handlefw);
}



exit(0);
