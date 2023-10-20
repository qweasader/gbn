# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113245");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-07 11:30:00 +0200 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Autonomic Controls Devices No Authentication (Telnet)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_autonomic_controls_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("autonomic_controls/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Per default, Autonomic Controls devices
  don't have authentication enabled for remote configuration.");

  script_tag(name:"vuldetect", value:"Checks if credentials are required
  to access the device.");

  script_tag(name:"impact", value:"Successful exploitation would give an attacker
  full control over the target device. Furthermore, the device stores account credentials
  in plain base64-encoding, allowing attackers access to linked Spotify, Amazon and other accounts.");

  script_tag(name:"affected", value:"All Autonomic Controls devices.");

  script_tag(name:"solution", value:"Set a password for remote configuration by accessing the telnet interface
  and executing following commands, whereas placeholders are placed in square brackets:

  set remote user [username]

  set remote password [password]");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

CPE = "cpe:/h:autonomic_controls:device";

include("host_details.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");

if( ! port = get_kb_item( "autonomic_controls/telnet/port" ) ) exit( 0 );

banner = telnet_get_banner( port: port );

if( banner =~ 'You are logged in' ) {
  report = "Accessing remote configuration didn't require authentication.";
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
