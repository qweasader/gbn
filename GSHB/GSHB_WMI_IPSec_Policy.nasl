# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96042");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-09 14:03:22 +0100 (Mon, 09 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Check over WMI if IPSec Policy used for Windows (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"The script detects over WMI if IPSec Policy used under Windows
  2000 and XP.");

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
OSNAME = get_kb_item("WMI/WMI_OSNAME");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/IPSecPolicy", value:"error");
  set_kb_item(name:"WMI/IPSecPolicy/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handlereg){
  set_kb_item(name:"WMI/IPSecPolicy", value:"error");
  set_kb_item(name:"WMI/IPSecPolicy/log", value:"wmi_connect: WMI Connect failed.");
  exit(0);
}

GPTIPSECPolicy = wmi_reg_enum_value(wmi_handle:handlereg, key:"SOFTWARE\Policies\Microsoft\Windows\IPSec\GPTIPSECPolicy");

if (OSVER < 6){
  NoDefaultExempt = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\IPSEC", val_name:"NoDefaultExempt");
  if (!NoDefaultExempt) NoDefaultExempt = "-1";
}else{
  NoDefaultExempt = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\PolicyAgent", val_name:"NoDefaultExempt");
  if (!NoDefaultExempt) NoDefaultExempt = "-1";
}
if(!GPTIPSECPolicy){
  log_message(port:0, proto: "IT-Grundschutz", data:"Registry Path 'SOFTWARE\Policies\Microsoft\Windows\IPSec\GPTIPSECPolicy' not found.");
  set_kb_item(name:"WMI/IPSecPolicy", value:"off");
  set_kb_item(name:"WMI/NoDefaultExempt", value:NoDefaultExempt);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

#if (OSVER == '5.0' ||  OSVER == '5.1' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition')
#{
  if (GPTIPSECPolicy)
  {
    if (OSVER < 6){
      DomPolicyPath = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Policies\Microsoft\Windows\IPSec\GPTIPSECPolicy", key_name:"DSIPSECPolicyPath");

      DomPolicyPath = split(DomPolicyPath, sep:",", keep:0);
      DomPolicyPath = ereg_replace(pattern:'LDAP://CN=ipsecPolicy',replace:'', string:DomPolicyPath[0]);
      key = "SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecPolicy" + DomPolicyPath;
      ActiveDomPolicy = wmi_reg_get_sz(wmi_handle:handlereg, key:key, key_name:"ipsecName");
    }else{
      ActiveDomPolicy = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Policies\Microsoft\Windows\IPSec\GPTIPSECPolicy", key_name:"DSIPSECPolicyName");
    }
    set_kb_item(name:"WMI/IPSecPolicy", value:ActiveDomPolicy);
  }
  else
  {
    PolicyPath = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local", key_name:"ActivePolicy");
    ActivePolicy = wmi_reg_get_sz(wmi_handle:handlereg, key:PolicyPath, key_name:"ipsecName");
    set_kb_item(name:"WMI/IPSecPolicy", value:ActivePolicy);
  }

  if (!ActiveDomPolicy && !ActivePolicy) set_kb_item(name:"WMI/IPSecPolicy", value:"off");
  set_kb_item(name:"WMI/NoDefaultExempt", value:NoDefaultExempt);
  wmi_close(wmi_handle:handlereg);
  exit(0);

#}
#else
#{
#  set_kb_item(name:"WMI/IPSecPolicy", value:"inapplicable");
#  log_message(port:0, proto: "IT-Grundschutz", data:string("No Windows 2000 or Windows XP"));
#  exit(0);
#}
