# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96050");
  script_version("2024-02-26T14:36:40+0000");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Read all EventLog Config Policy (ELCP) Settings - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"The script read all, Vista and above, EventLog Config Policy Settings.");

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
  set_kb_item(name:"WMI/ELCP/GENERAL", value:"error");
  set_kb_item(name:"WMI/ELCP/GENERAL/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

if (OSVER < '6.0'){
    set_kb_item(name:"WMI/ELCP/GENERAL", value:"prevista");
    exit(0);
}

handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handlereg){
  log_message(port:0, data:"wmi_connect: WMI Connect failed.");
  set_kb_item(name:"WMI/ELCP/GENERAL", value:"error");
  set_kb_item(name:"WMI/ELCP/GENERAL/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

#Read Eventlog configuration for non Domainmembers
LocAppEventLMaxSize = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Eventlog\Application", val_name:"MaxSize");
LocSecEventLMaxSize = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Eventlog\Security", val_name:"MaxSize");
LocSysEventLMaxSize = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Eventlog\System", val_name:"MaxSize");

LocAppEventLRetention = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Eventlog\Application", val_name:"Retention");
LocSecEventLRetention = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Eventlog\Security", val_name:"Retention");
LocSysEventLRetention = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Eventlog\System", val_name:"Retention");

LocAppEventLRestrictGuestAccess = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Eventlog\Application", val_name:"RestrictGuestAccess");
LocSecEventLRestrictGuestAccess = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Eventlog\Security", val_name:"RestrictGuestAccess");
LocSysEventLRestrictGuestAccess = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Eventlog\System", val_name:"RestrictGuestAccess");

LocAppEventLAutoBackupLogFiles = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Eventlog\Application", val_name:"AutoBackupLogFiles");
LocSecEventLAutoBackupLogFiles = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Eventlog\Security", val_name:"AutoBackupLogFiles");
LocSysEventLAutoBackupLogFiles = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Eventlog\System", val_name:"AutoBackupLogFiles");


########################

AppEventLAutoBackupLogFiles = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Application", key_name:"AutoBackupLogFiles");
SecEventLAutoBackupLogFiles = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Security", key_name:"AutoBackupLogFiles");
SetEventLAutoBackupLogFiles = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Setup", key_name:"AutoBackupLogFiles");
SysEventLAutoBackupLogFiles = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\System", key_name:"AutoBackupLogFiles");

AppEventLChannelAccess = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Application", key_name:"ChannelAccess");
SecEventLChannelAccess = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Security", key_name:"ChannelAccess");
SetEventLChannelAccess = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Setup", key_name:"ChannelAccess");
SysEventLChannelAccess = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\System", key_name:"ChannelAccess");

SetEventLEnable = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Setup", key_name:"Enabled");

AppEventLFile = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Application", key_name:"File");
SecEventLFile = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Security", key_name:"File");
SetEventLFile = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Setup", key_name:"File");
SysEventLFile = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\System", key_name:"File");

AppEventLMaxSize = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Application", val_name:"MaxSize");
SecEventLMaxSize = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Security", val_name:"MaxSize");
SetEventLMaxSize = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Setup", val_name:"MaxSize");
SysEventLMaxSize = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\System", val_name:"MaxSize");

AppEventLRetention = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Application", key_name:"Retention");
SecEventLRetention = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Security", key_name:"Retention");
SetEventLRetention = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\Setup", key_name:"Retention");
SysEventLRetention = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\EventLog\System", key_name:"Retention");

val = "None";

if(AppEventLAutoBackupLogFiles == "0" || AppEventLAutoBackupLogFiles){
  set_kb_item(name:"WMI/ELCP/AppEventLAutoBackupLogFiles", value:AppEventLAutoBackupLogFiles);
}else  set_kb_item(name:"WMI/ELCP/AppEventLAutoBackupLogFiles", value:val);

if(SecEventLAutoBackupLogFiles == "0" || SecEventLAutoBackupLogFiles){
  set_kb_item(name:"WMI/ELCP/SecEventLAutoBackupLogFiles", value:SecEventLAutoBackupLogFiles);
}else  set_kb_item(name:"WMI/ELCP/SecEventLAutoBackupLogFiles", value:val);

if(SetEventLAutoBackupLogFiles == "0" || SetEventLAutoBackupLogFiles){
  set_kb_item(name:"WMI/ELCP/SetEventLAutoBackupLogFiles", value:SetEventLAutoBackupLogFiles);
}else  set_kb_item(name:"WMI/ELCP/SetEventLAutoBackupLogFiles", value:val);

if(SysEventLAutoBackupLogFiles == "0" || SysEventLAutoBackupLogFiles){
  set_kb_item(name:"WMI/ELCP/SysEventLAutoBackupLogFiles", value:SysEventLAutoBackupLogFiles);
}else  set_kb_item(name:"WMI/ELCP/SysEventLAutoBackupLogFiles", value:val);

if(AppEventLChannelAccess == "0" || AppEventLChannelAccess){
  set_kb_item(name:"WMI/ELCP/AppEventLChannelAccess", value:AppEventLChannelAccess);
}else  set_kb_item(name:"WMI/ELCP/AppEventLChannelAccess", value:val);

if(SecEventLChannelAccess == "0" || SecEventLChannelAccess){
  set_kb_item(name:"WMI/ELCP/SecEventLChannelAccess", value:SecEventLChannelAccess);
}else  set_kb_item(name:"WMI/ELCP/SecEventLChannelAccess", value:val);

if(SetEventLChannelAccess == "0" || SetEventLChannelAccess){
  set_kb_item(name:"WMI/ELCP/SetEventLChannelAccess", value:SetEventLChannelAccess);
}else  set_kb_item(name:"WMI/ELCP/SetEventLChannelAccess", value:val);

if(SysEventLChannelAccess == "0" || SysEventLChannelAccess){
  set_kb_item(name:"WMI/ELCP/SysEventLChannelAccess", value:SysEventLChannelAccess);
}else  set_kb_item(name:"WMI/ELCP/SysEventLChannelAccess", value:val);

if(SetEventLEnable == "0" || SetEventLEnable){
  set_kb_item(name:"WMI/ELCP/SetEventLEnable", value:SetEventLEnable);
}else  set_kb_item(name:"WMI/ELCP/SetEventLEnable", value:val);

if(AppEventLFile == "0" || AppEventLFile){
  set_kb_item(name:"WMI/ELCP/AppEventLFile", value:AppEventLFile);
}else  set_kb_item(name:"WMI/ELCP/AppEventLFile", value:val);

if(SecEventLFile == "0" || SecEventLFile){
  set_kb_item(name:"WMI/ELCP/SecEventLFile", value:SecEventLFile);
}else  set_kb_item(name:"WMI/ELCP/SecEventLFile", value:val);

if(SetEventLFile == "0" || SetEventLFile){
  set_kb_item(name:"WMI/ELCP/SetEventLFile", value:SetEventLFile);
}else  set_kb_item(name:"WMI/ELCP/SetEventLFile", value:val);

if(SysEventLFile == "0" || SysEventLFile){
  set_kb_item(name:"WMI/ELCP/SysEventLFile", value:SysEventLFile);
}else  set_kb_item(name:"WMI/ELCP/SysEventLFile", value:val);

if(AppEventLMaxSize != "0" || AppEventLMaxSize){
  set_kb_item(name:"WMI/ELCP/AppEventLMaxSize", value:AppEventLMaxSize);
}else  set_kb_item(name:"WMI/ELCP/AppEventLMaxSize", value:val);

if(SecEventLMaxSize != "0" || SecEventLMaxSize){
  set_kb_item(name:"WMI/ELCP/SecEventLMaxSize", value:SecEventLMaxSize);
}else  set_kb_item(name:"WMI/ELCP/SecEventLMaxSize", value:val);

if(SetEventLMaxSize != "0" || SetEventLMaxSize){
  set_kb_item(name:"WMI/ELCP/SetEventLMaxSize", value:SetEventLMaxSize);
}else  set_kb_item(name:"WMI/ELCP/SetEventLMaxSize", value:val);

if(SysEventLMaxSize != "0" || SysEventLMaxSize){
  set_kb_item(name:"WMI/ELCP/SysEventLMaxSize", value:SysEventLMaxSize);
}else  set_kb_item(name:"WMI/ELCP/SysEventLMaxSize", value:val);

if(AppEventLRetention == "0" || AppEventLRetention){
  set_kb_item(name:"WMI/ELCP/AppEventLRetention", value:AppEventLRetention);
}else  set_kb_item(name:"WMI/ELCP/AppEventLRetention", value:val);

if(SecEventLRetention == "0" || SecEventLRetention){
  set_kb_item(name:"WMI/ELCP/SecEventLRetention", value:SecEventLRetention);
}else  set_kb_item(name:"WMI/ELCP/SecEventLRetention", value:val);

if(SetEventLRetention == "0" || SetEventLRetention){
  set_kb_item(name:"WMI/ELCP/SetEventLRetention", value:SetEventLRetention);
}else  set_kb_item(name:"WMI/ELCP/SetEventLRetention", value:val);

if(SysEventLRetention == "0" || SysEventLRetention){
  set_kb_item(name:"WMI/ELCP/SysEventLRetention", value:SysEventLRetention);
}else  set_kb_item(name:"WMI/ELCP/SysEventLRetention", value:val);

if(LocAppEventLMaxSize == "0" || LocAppEventLMaxSize){
  set_kb_item(name:"WMI/ELCP/LocAppEventLMaxSize", value:LocAppEventLMaxSize);
}else  set_kb_item(name:"WMI/ELCP/LocAppEventLMaxSize", value:val);

if(LocSecEventLMaxSize == "0" || LocSecEventLMaxSize){
  set_kb_item(name:"WMI/ELCP/LocSecEventLMaxSize", value:LocSecEventLMaxSize);
}else  set_kb_item(name:"WMI/ELCP/LocSecEventLMaxSize", value:val);

if(LocSysEventLMaxSize == "0" || LocSysEventLMaxSize){
  set_kb_item(name:"WMI/ELCP/LocSysEventLMaxSize", value:LocSysEventLMaxSize);
}else  set_kb_item(name:"WMI/ELCP/LocSysEventLMaxSize", value:val);

if(LocAppEventLRetention == "0" || LocAppEventLRetention){
  set_kb_item(name:"WMI/ELCP/LocAppEventLRetention", value:LocAppEventLRetention);
}else  set_kb_item(name:"WMI/ELCP/LocAppEventLRetention", value:val);

if(LocSecEventLRetention == "0" || LocSecEventLRetention){
  set_kb_item(name:"WMI/ELCP/LocSecEventLRetention", value:LocSecEventLRetention);
}else  set_kb_item(name:"WMI/ELCP/LocSecEventLRetention", value:val);

if(LocSysEventLRetention == "0" || LocSysEventLRetention){
  set_kb_item(name:"WMI/ELCP/LocSysEventLRetention", value:LocSysEventLRetention);
}else  set_kb_item(name:"WMI/ELCP/LocSysEventLRetention", value:val);

if(LocAppEventLRestrictGuestAccess == "0" || LocAppEventLRestrictGuestAccess){
  set_kb_item(name:"WMI/ELCP/LocAppEventLRestrictGuestAccess", value:LocAppEventLRestrictGuestAccess);
}else  set_kb_item(name:"WMI/ELCP/LocAppEventLRestrictGuestAccess", value:val);

if(LocSecEventLRestrictGuestAccess == "0" || LocSecEventLRestrictGuestAccess){
  set_kb_item(name:"WMI/ELCP/LocSecEventLRestrictGuestAccess", value:LocSecEventLRestrictGuestAccess);
}else  set_kb_item(name:"WMI/ELCP/LocSecEventLRestrictGuestAccess", value:val);

if(LocSysEventLRestrictGuestAccess == "0" || LocSysEventLRestrictGuestAccess){
  set_kb_item(name:"WMI/ELCP/LocSysEventLRestrictGuestAccess", value:LocSysEventLRestrictGuestAccess);
}else  set_kb_item(name:"WMI/ELCP/LocSysEventLRestrictGuestAccess", value:val);

if(LocAppEventLAutoBackupLogFiles == "0" || LocAppEventLAutoBackupLogFiles){
  set_kb_item(name:"WMI/ELCP/LocAppEventLAutoBackupLogFiles", value:LocAppEventLAutoBackupLogFiles);
}else  set_kb_item(name:"WMI/ELCP/LocAppEventLAutoBackupLogFiles", value:val);

if(LocSecEventLAutoBackupLogFiles == "0" || LocSecEventLAutoBackupLogFiles){
  set_kb_item(name:"WMI/ELCP/LocSecEventLAutoBackupLogFiles", value:LocSecEventLAutoBackupLogFiles);
}else  set_kb_item(name:"WMI/ELCP/LocSecEventLAutoBackupLogFiles", value:val);

if(LocSysEventLAutoBackupLogFiles == "0" || LocSysEventLAutoBackupLogFiles){
  set_kb_item(name:"WMI/ELCP/LocSysEventLAutoBackupLogFiles", value:LocSysEventLAutoBackupLogFiles);
}else  set_kb_item(name:"WMI/ELCP/LocSysEventLAutoBackupLogFiles", value:val);

wmi_close(wmi_handle:handlereg);
set_kb_item(name:"WMI/ELCP/GENERAL", value:"ok");
exit(0);


