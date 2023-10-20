# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112041");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-09-15 08:40:00 +0200 (Fri, 15 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Remove deprecated Authenticated Scan supporting service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows");
  script_dependencies("toolcheck.nasl", "smb_registry_access.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_access", "Tools/Present/wmi");
  script_exclude_keys("win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"In the past, during an Authenticated Scan, it was sometimes necessary to deploy a
  service onto the target machine. As this method is deprecated now, the service is removed.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

if(get_kb_item("win/lsc/disable_win_cmd_exec"))
  exit(0);

username = kb_smb_login();
password = kb_smb_password();

if(!username)
  exit(0);

domain = kb_smb_domain();
if(domain)
  username = domain + "/" + username;

service  = "winexesvc";
command  = "sc query " + service;
response = win_cmd_exec(cmd:command, username:username, password:password);

if("RUNNING" >< response) {
  command  = "sc stop " + service;
  response = win_cmd_exec(cmd:command, username:username, password:password);
}

if("STOPPED" >< response) {
  command = "sc delete " + service;
  win_cmd_exec(cmd:command, username:username, password:password);
}

exit(0);
