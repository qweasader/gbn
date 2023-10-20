# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150202");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-04-09 08:31:24 +0000 (Thu, 09 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Aging Time of Non-Authentication Sessions");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "zsql_dv_parameters.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"60", id:1);

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"To prevent DOS attacks from malicious clients that occupy server
resources. Set the UNAUTH_SESSION_EXPIRE_TIME parameter to forcibly disconnect from the server if
no authentication is performed at the specified time after the TCP connection is established.");

  exit(0);
}

include("policy_functions.inc");

cmd = "SELECT NAME, VALUE FROM DV_PARAMETERS WHERE NAME = 'UNAUTH_SESSION_EXPIRE_TIME';";
title = "Aging Time of Non-Authentication Sessions";
solution = "Set UNAUTH_SESSION_EXPIRE_TIME in {GSDB_DATA}/cfg/zengine.ini and restart the database
for the setting to take effect. Or run the ALTER SYSTEM statement to set UNAUTH_SESSION_EXPIRE_TIME.
ALTER SYSTEM SET UNAUTH_SESSION_EXPIRE_TIME = 60 SCOPE = BOTH;";
test_type = "SQL_Query";
default = script_get_preference("Value", id:1);
default = "60";

if(get_kb_item("Policy/zsql/dv_parameters/ssh/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/zsql/dv_parameters/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not read table DV_PARAMETERS";
}else if(!value = get_kb_item("Policy/zsql/dv_parameters/UNAUTH_SESSION_EXPIRE_TIME/value")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not find value for UNAUTH_SESSION_EXPIRE_TIME in table DV_PARAMETERS";
}else{
  compliant = policy_setting_max_match(value:value, set_point:default);
}

policy_reporting(result:value, default:"<= " + default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
