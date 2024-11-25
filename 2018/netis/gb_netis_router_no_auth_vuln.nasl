# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:netis-systems:";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113304");
  script_version("2024-02-27T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-27 14:36:53 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-11-15 10:40:22 +0100 (Thu, 15 Nov 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Netis Router No Authentication Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_netis_router_consolidation.nasl");
  script_mandatory_keys("netis/router/http/detected");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"Netis Routers do not require authentication by default.");

  script_tag(name:"vuldetect", value:"Checks if the web interface is accessible without
  authentication.");

  script_tag(name:"impact", value:"Without a password, any remote attacker can access the device
  with administrative privileges.");

  script_tag(name:"solution", value:"In the 'Advanced' Settings, go to 'System Tools' -> 'Password'
  and set a username and a secure password.");

  script_xref(name:"URL", value:"http://www.netis-systems.com/Home/info/id/2.html");
  script_xref(name:"URL", value:"http://www.netis-systems.com/Business/info/id/2.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www", first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

url_one = "/script/netcore.js";
url_two = "/config/config.js";

buf_one = http_get_cache(port: port, item: url_one);
buf_two = http_get_cache(port: port, item: url_two);

if (buf_one =~ "^HTTP/1\.[01] 200" && "var netcore" >< buf_one && "Basic realm" >!< buf_one &&
    "WWW-Authenticate" >!< buf_one &&
    buf_two =~ "^HTTP/1\.[01] 200" && buf_two =~ 'name\\s*:\\s*"management"') {
  report = "It was possible to access the admin interface without login credentials.";
  security_message(port: port,  data: report);
  exit(0);
}

exit(99);
