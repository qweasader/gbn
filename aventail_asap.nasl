# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17583");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Aventail ASAP detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports(8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Filter incoming traffic to this port.");

  script_tag(name:"summary", value:"The remote host seems to be an Aventail SSL VPN appliance,
  connections are allowed to the web console management.

  Letting attackers know that you are using this software will help
  them to focus their attack or will make them change their strategy.

  In addition to this, an attacker may attempt to set up a brute force attack
  to log into the remote interface.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");

port = 8443;
if(!get_port_state(port))
  exit(0);

url = "/console/login.do";
req = http_get(item:url, port:port);
rep = http_send_recv(data:req, port:port);
if(!rep)
  exit(0);

#<title>ASAP Management Console Login</title>
if ("<title>ASAP Management Console Login</title>" >< rep) {
  report = http_report_vuln_url(port:port, url:url);
  log_message(port:port, data:report);
  exit(0);
}

exit(99);
