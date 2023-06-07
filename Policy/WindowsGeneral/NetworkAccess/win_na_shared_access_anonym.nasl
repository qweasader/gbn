# Copyright (C) 2018 Greenbone Networks GmbH
#
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109227");
  script_version("2021-05-26T11:52:35+0000");
  script_tag(name:"last_modification", value:"2021-05-26 11:52:35 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2018-06-11 14:53:35 +0200 (Mon, 11 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Network access: Shares that can be accessed anonymously");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"None", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 2.3.10.11 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 2.3.10.12 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 14.6 Protect Information through Access Control Lists");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This security setting determines which network shares can
accessed by anonymous users.

(C) Microsoft Corporation 2015.

Note: This policy check will report compliance by default if the key is empty or missing.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Network access: Shares that can be accessed anonymously";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/" + title;
type = "HKLM";
key = "System\CurrentControlSet\Services\LanManServer\Parameters";
item = "nullsessionshares";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Value", id:1);

if(!policy_verify_win_ver(min_ver:win_min_ver)){
  results = policy_report_wrong_os(target_os:target_os);
}else{
  results = policy_match_reg_sz(key:key, item:item, type:type, default:default);
}

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

if(value == "Unknown"){
  compliant = "yes";
  value = "None";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
