# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150200");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-04-08 14:20:28 +0000 (Wed, 08 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: IP Address Blacklist");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "zsql_dv_parameters.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");

  script_tag(name:"summary", value:"The IP address blacklist is configured by setting the
TCP_EXCLUDED_NODES parameter. After IP address whitelist/blacklist checking is enabled and the IP
address blacklist is configured, the blacklisted clients cannot access the database. Such a
blacklist allows for IPv4 and IPv6 addresses, as well as a specified subnet mask or prefix length,
which indicates a network segment. Multiple addresses or network segments can be separated by commas
(,).

Note: This script shows the excluded nodes only. Please check manually for compliance.");

  exit(0);
}

include("policy_functions.inc");

cmd = "SELECT NAME, VALUE FROM DV_PARAMETERS WHERE NAME = 'TCP_EXCLUDED_NODES';";
title = "IP Address Blacklist";
solution = "Add IPv4, IPv6 or network segments to the IP address blacklist:
ALTER SYSTEM SET TCP_EXCLUDED_NODES = = '(IPv4,IPv6)';
ALTER SYSTEM SET TCP_EXCLUDED_NODES = '(IPv4/24)';";
test_type = "SQL_Query";
default = "Not Empty";

if(get_kb_item("Policy/zsql/dv_parameters/ssh/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/zsql/dv_parameters/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not read table DV_PARAMETERS";
}else if(!value = get_kb_item("Policy/zsql/dv_parameters/TCP_EXCLUDED_NODES/value")){
  compliant = "no";
  value = "None";
  comment = "Can not find value for TCP_EXCLUDED_NODES in table DV_PARAMETERS";
}else{
  compliant = "yes";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
