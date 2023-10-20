# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.116101");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-03-04 08:00:00 +0000 (Thu, 04 Mar 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("MySQL: Authentication Parameters");

  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Compliance");
  script_dependencies("compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"User", type:"entry", value:"SYS", id:1);
  script_add_preference(name:"Password", type:"password", value:"Changeme_123", id:2);
  script_add_preference(name:"IP", type:"entry", value:"127.0.0.1", id:3);
  script_add_preference(name:"Port", type:"entry", value:"3306", id:4);

  script_xref(name:"URL", value:"https://dev.mysql.com/doc/refman/5.7/en/introduction.html");
  script_tag(name:"summary", value:"Enter credentials for using a different user, password, ip or port for MySQL Policy Controls.");

  exit(0);
}

user = script_get_preference( "User", id:1 );
if ( user != "" )
  set_kb_item( name:"Policy/mysql/user", value:user );
else
  set_kb_item( name:"Policy/mysql/user", value:"SYS" );

password = script_get_preference( "Password", id:2 );
if ( password != "" )
  set_kb_item( name:"Policy/mysql/password", value:password );
else
  set_kb_item( name:"Policy/mysql/password", value:"Changeme_123" );

ip = script_get_preference( "IP", id:3 );
if ( ip != "" )
  set_kb_item( name:"Policy/mysql/ip", value:ip );
else
  set_kb_item( name:"Policy/mysql/ip", value:"127.0.0.1" );

port = script_get_preference( "Port", id:4 );
if ( port != "" )
  set_kb_item( name:"Policy/mysql/port", value:port );
else
  set_kb_item( name:"Policy/mysql/port", value:"3306" );

exit(0);