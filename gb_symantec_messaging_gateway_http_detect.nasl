# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105720");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-12-03 10:06:00 +0100 (Mon, 03 Dec 2012)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Symantec Messaging Gateway Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Symantec Messaging Gateway over HTTP.

The script sends a connection request to the server and attempts to detect Symantec Messaging Gateway and
to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:443);

url = '/brightmail/viewLogin.do';
res = http_get_cache(item:url, port:port);

if (egrep(pattern: "<title>Symantec Messaging Gateway -&nbsp;Login", string: res, icase:TRUE) ||
    ("Symantec Messaging Gateway -&nbsp;" >< res && "Symantec Corporation" >< res &&
     "images/Symantec_Logo.png" >< res) ||
     "<title>Symantec Messaging Gateway -&nbsp;Error 403</title>" >< res) {
  set_kb_item(name: "symantec_smg/detected", value: TRUE);
  set_kb_item(name: "symantec_smg/http/detected", value: TRUE);
  set_kb_item(name: "symantec_smg/http/port", value: port);

  vers = eregmatch(string: res, pattern: "Version ([0-9.]+)", icase: TRUE);
  if (!isnull(vers[1])) {
    set_kb_item(name:"symantec_smg/http/" + port + "/version", value: vers[1]);
    set_kb_item(name:"symantec_smg/http/" + port + "/concluded", value: vers[0]);
  }
}

exit(0);
