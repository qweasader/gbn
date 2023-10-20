# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109604");
  script_version("2023-08-23T05:05:12+0000");
  script_tag(name:"last_modification", value:"2023-08-23 05:05:12 +0000 (Wed, 23 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-09-13 12:46:22 +0200 (Thu, 13 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("Microsoft Windows: Turn On Virtualization Based Security (Credential Guard Configuration)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"0;1;2;3", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 8.9.5.5 (NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"Specifies whether Virtualization Based Security is enabled.

Virtualization Based Security uses the Windows Hypervisor to provide support for security services.
Virtualization Based Security requires Secure Boot, and can optionally be enabled with the use of
DMA Protections. DMA protections require hardware support and will only be enabled on correctly
configured devices.

Credential Guard

This setting lets users turn on Credential Guard with virtualization-based security to help protect
credentials.

The 'Disabled' option turns off Credential Guard remotely if it was previously turned on with the
'Enabled without lock' option.

The 'Enabled with UEFI lock' option ensures that Credential Guard cannot be disabled remotely. In
order to disable the feature, you must set the Group Policy to 'Disabled' as well as remove the
security functionality from each computer, with a physically present user, in order to clear
configuration persisted in UEFI.

The 'Enabled without lock' option allows Credential Guard to be disabled remotely by using Group
Policy. The devices that use this setting must be running at least Windows 10 (Version 1511).

The 'Not Configured' option leaves the policy setting undefined. Group Policy does not write the
policy setting to the registry, and so it has no impact on computers or users. If there is a current
setting in the registry it will not be modified.

(C) 2015 Microsoft Corporation.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("version_func.inc");

target_os = "Microsoft Windows 8.1 or later";
win_min_ver = "6.3";
title = "Turn On Virtualization Based Security (Credential Guard Configuration)";
solution = "Set following UI path accordingly:
Computer Configuration/Administrative Templates/System/Device Guard/" + title;
test_type = "RegKey";
type = "HKLM";
key = "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
item = "LsaCfgFlags";
reg_path = type + "\" + key + "!" + item;
default = script_get_preference("Value");

if(!policy_verify_win_ver(min_ver:win_min_ver)){
  results = policy_report_wrong_os(target_os:target_os);
}else{
  results = policy_match_exact_reg_dword(key:key, item:item, type:type, default:default);
}

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);