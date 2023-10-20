# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100280");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BigAnt IM Server Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("AntServer/banner");
  script_require_ports("Services/www", 6660);

  script_tag(name:"summary", value:"This host is running BigAnt IM Server, an instant messaging solution
  for enterprise.");

  script_xref(name:"URL", value:"http://www.bigantsoft.com/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:6660);
banner = http_get_remote_headers(port:port);
if(!banner)
  exit(0);

if(egrep(pattern:"Server: AntServer", string:banner, icase:TRUE)) {
  service_register(port:port, ipproto:"tcp", proto:"BigAnt");
  set_kb_item(name:"bigant/server/detected", value:TRUE);
  log_message(port:port);
}

exit(0);
