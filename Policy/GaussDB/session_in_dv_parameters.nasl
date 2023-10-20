# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150197");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-04-08 13:47:31 +0000 (Wed, 08 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Maximum Number of Connections");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "zsql_dv_parameters.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"69", id:1);
  script_add_preference(name:"Maximum", type:"entry", value:"8192", id:2);

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"If the maximum number of online connections is set to a large
value, the required process socket handles and session pool memory may exceed the OS limit on the
server.

  - Value: The minimum value to be compliant.

  - Maximum: The maximum value to be compliant.");

  exit(0);
}

include("policy_functions.inc");

cmd = "SELECT NAME, VALUE FROM DV_PARAMETERS WHERE NAME = 'SESSIONS';";
title = "Maximum Number of Connections";
solution = "Change the value of SESSIONS in the zengine.ini configuration file and restart the
database for the change to take effect. The path of the zengine.ini file is {GSDB_DATA}/cfg/zengine.ini.";
test_type = "SQL_Query";
minimum = script_get_preference("Value", id:1);
maximum = script_get_preference("Maximum", id:2);
default = minimum + "-" + maximum;

if(get_kb_item("Policy/zsql/dv_parameters/ssh/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/zsql/dv_parameters/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not read table DV_PARAMETERS";
}else if(!value = get_kb_item("Policy/zsql/dv_parameters/SESSIONS/value")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not find value for SESSIONS in table DV_PARAMETERS";
}else{
  compliant = policy_setting_in_range(value:value, min:minimum, max:maximum);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
