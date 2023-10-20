# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103695");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Tandberg Devices Default Credentials (Telnet)");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-04-10 12:01:48 +0100 (Wed, 10 Apr 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_tandberg_devices_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports(23);
  script_mandatory_keys("host_is_tandberg_device");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"summary", value:"The remote Tandberg device has the default password 'TANDBERG'.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");

port = 23;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

buf = telnet_negotiate(socket:soc);

if("Password:" >!< buf)exit(0);

send(socket:soc, data:'TANDBERG\n');
recv = recv(socket:soc, length:512);

if("OK" >!< recv)exit(0);

send(socket:soc, data:'ifconfig\n');
recv = recv(socket:soc, length:512);

send(socket:soc, data:'exit\n');

if("HWaddr" >< recv && "Inet addr" >< recv) {

  security_message(port:port);
  exit(0);

}

exit(99);

