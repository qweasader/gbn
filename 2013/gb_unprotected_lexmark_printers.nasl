# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103686");
  script_version("2024-03-07T05:06:18+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-07 05:06:18 +0000 (Thu, 07 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-03-28 11:51:27 +0100 (Thu, 28 Mar 2013)");

  script_name("Unprotected Lexmark Printer (HTTP)");

  script_category(ACT_ATTACK);

  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  # nb: No need to disable via default_credentials/disable_default_account_checks or
  # gb_default_credentials_options.nasl because this isn't doing any login (at least currently)...
  script_dependencies("gb_lexmark_printer_consolidation.nasl");
  script_mandatory_keys("lexmark_printer/http/detected", "lexmark_printer/model");

  script_tag(name:"summary", value:"The remote Lexmark Printer is not protected by a password and/or permissions
  for default users are too lose.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration without requiring authentication.");

  script_tag(name:"solution", value:"Set a password and/or restrict permissions for default users.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("lexmark_printers.inc");
include("http_func.inc");
include("misc_func.inc");

CPE_PREFIX = "cpe:/o:lexmark:";

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

port = infos["port"];
cpe = infos["cpe"];

if( ! get_app_location( cpe:cpe, port:port, nofork:TRUE ) )
  exit( 0 );

model = get_kb_item( "lexmark_printer/model" );
if( ! model )
  exit( 0 );

ret = check_lexmark_default_login( model:model, port:port );
if( ret && ret == 2 ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
