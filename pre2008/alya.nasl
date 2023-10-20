# SPDX-FileCopyrightText: 2002 Jason Lidow
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11118");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("alya.cgi");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Jason Lidow");
  script_family("Malware");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"alya.cgi is a cgi backdoor distributed with
  multiple rootkits.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"solution", value:"A whole clean up of the affected system
  is recommended.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
res = http_is_cgi_installed_ka(port:port, item:"alya.cgi");
if(res) {
  security_message(port:port);
  exit(0);
}

exit(99);
