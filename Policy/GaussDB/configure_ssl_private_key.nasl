# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.150201");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-04-09 06:56:20 +0000 (Thu, 09 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Configure private SSL key");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "zsql_dv_parameters.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");

  script_tag(name:"summary", value:"The database parameters _FACTOR_KEY and LOCAL_KEY must be
updated in time to ensure the security of SSL private key encryption.");

  exit(0);
}

include("policy_functions.inc");

cmd = "SELECT NAME, VALUE FROM DV_PARAMETERS WHERE (NAME = '_FACTOR_KEY' AND VALUE =
'dc4hoQWGQs7/Uv3AiherFw==') or (NAME = 'LOCAL_KEY' AND VALUE =
'UTiYlBoTC71MvTyBvWhVDodc0VAop1GMe135ZCov8Pv4xsnlEHn9Bs/pjRo7ZNM1BXq8Z4XuyRjfaNpY/7McEQ==');";
title = "Configure private SSL key";
solution = "Create _FACTOR_KEY and LOCAL_KEY with 'zencrypt -g' and run ALTER SYSTEM command:
ALTER SYSTEM SET _FACTOR_KEY = NEW_KEY;
ALTER SYSTEM SET LOCAL_KEY = NEW_KEY;";
test_type = "SQL_Query";
default = "_FACTOR_KEY not 'dc4hoQWGQs7/Uv3AiherFw==', LOCAL_KEY not 'UTiYlBoTC71MvTyBvWhVDodc0VAop1GMe135ZCov8Pv4xsnlEHn9Bs/pjRo7ZNM1BXq8Z4XuyRjfaNpY/7McEQ=='";
compliant = "yes";

if(get_kb_item("Policy/zsql/dv_parameters/ssh/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/zsql/dv_parameters/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not read table DV_PARAMETERS";
}else if((!_FACTOR_KEY = get_kb_item("Policy/zsql/dv_parameters/_FACTOR_KEY/value")) ||
  (!LOCAL_KEY = get_kb_item("Policy/zsql/dv_parameters/LOCAL_KEY/value"))){
  compliant = "incomplete";
  value = "None";
  comment = "Can not find value for _FACTOR_KEY or LOCAL_KEY in table DV_PARAMETERS";
}else{
  if(_FACTOR_KEY == "dc4hoQWGQs7/Uv3AiherFw==" ||
    LOCAL_KEY == "UTiYlBoTC71MvTyBvWhVDodc0VAop1GMe135ZCov8Pv4xsnlEHn9Bs/pjRo7ZNM1BXq8Z4XuyRjfaNpY/7McEQ==")
    compliant = "no";

  value = "_FACTOR_KEY: '" + _FACTOR_KEY + "', LOCAL_KEY: '" + LOCAL_KEY + "'";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
