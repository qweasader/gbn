# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109522");
  script_version("2023-08-22T05:06:00+0000");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-28 16:31:48 +0200 (Thu, 28 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows 10: Do not use diagnostic data for tailored experiences");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl", "os_detection.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"1;0", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 19.7.7.3 (L2) Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled' (Automated)");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting lets you prevent Windows from using
diagnostic data to provide tailored experiences to the user.

If you enable this policy setting, Windows will not use diagnostic data from this device (this data
may include browser, app and feature usage, depending on the 'diagnostic data' setting value) to
customize content shown on lock screen, Windows tips, Microsoft consumer features and other related
features. If these features are enabled, users will still see recommendations, tips and offers, but
they may be less relevant.

If you disable or do not configure this policy setting, Microsoft will use diagnostic data to provide
personalized recommendations, tips and offers to tailor Windows for the user's needs, and make it
work better for them.

Note: this setting does not control Cortana tailored experiences, since there are separate policies
to configure it.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = policy_microsoft_windows_target_string();
title = "Do not use diagnostic data for tailored experiences";
solution = "Set following UI path accordingly:
User Configuration/Administrative Templates/Windows Components/Cloud Content/" + title;
type = "HKU";
key = "Software\Policies\Microsoft\Windows\CloudContent";
item = "DisableTailoredExperiencesWithDiagnosticData";
reg_path = type + "\[SID]\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Value");

if(!policy_verify_win_ver())
  results = policy_report_wrong_os(target_os:target_os);
else if(!sids = registry_hku_subkeys())
  results = policy_report_empty_hku();
else
  results = policy_match_exact_dword_profiles(key:key, item:item, default:default, sids:sids);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
