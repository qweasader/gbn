# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109001");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-06-23 12:03:14 +0200 (Fri, 23 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Read all Windows Policy Security Settings - Windows");
  script_family("Policy");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_tag(name:"summary", value:"Read all Windows Advanced Policy Security Settings (Windows).

Note: This script saves into DB only and does not report any output.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

if(!policy_verify_win_ver(min_ver:"6.1")){
    policy_logging(text:'Host is not at least a Microsoft Windows 7 system. Older versions of
Windows are not supported any more. Please update the Operating System.', error:TRUE);
}

usrname = kb_smb_login();
domain  = kb_smb_domain();

if (domain){
  usrname = domain + '/' + usrname;
}
passwd = kb_smb_password();

if( get_kb_item( "win/lsc/disable_win_cmd_exec" ) ) {
  policy_logging(text:'Error: Usage of win_cmd_exec required for this check was disabled manually
within "Options for Local Security Checks (OID: 1.3.6.1.4.1.25623.1.0.100509)".', error:TRUE);
  exit(0);
}

AdvancedPolicy = win_cmd_exec(cmd:"auditpol /get /category:*", password:passwd, username:usrname);
pnpaudit = win_cmd_exec(cmd:"auditpol /get /subcategory:`Plug and Play Events`", password:passwd, username:usrname);

if(!AdvancedPolicy || "smb sessionerror" >< tolower(AdvancedPolicy)){
  policy_logging(text:'Error: Could not query the audit policy.', error:TRUE);
  exit(0);
}

AdvancedPolicy = split(AdvancedPolicy, keep:FALSE);
foreach pol (AdvancedPolicy) {
  name = eregmatch(string:pol, pattern:"^\s+(.*)\s{2,}(Success and Failure|Success|Failure|No Auditing)");
  if(chomp(name)){
    if("/" >< name[1]) name[1] = str_replace(string:name[1], find:"/", replace:"");
    key = "WMI/AdvancedPolicy/" + str_replace(string:name[1], find:" ", replace:"");
    value = name[2];
    set_kb_item(name:key, value:value);
  }
}

pnpaudit = split(pnpaudit, keep:FALSE);
foreach pol (pnpaudit) {
  name = eregmatch(string:pol, pattern:"^\s+(.*)\s{2,}(Success and Failure|Success|Failure|No Auditing)");
  if(chomp(name)){
    if("/" >< name[1]) name[1] = str_replace(string:name[1], find:"/", replace:"");
    key = "WMI/AdvancedPolicy/" + str_replace(string:name[1], find:" ", replace:"");
    value = name[2];
    set_kb_item(name:key, value:value);
  }
}

exit(0);
