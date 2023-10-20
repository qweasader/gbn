# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103575");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-09-25 12:05:19 +0200 (Tue, 25 Sep 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetMRI Detection");

  script_tag(name:"summary", value:"Detection of NetMRI.

The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:443);

data = 'mode=LOGIN-FORM';
url = "/netmri/config/userAdmin/login.tdf";

req = http_post(port: port, item: url, data: data);
res = http_keepalive_send_recv(port: port, data: req);

if ("<title>NetMRI Login" >< res || "<title>Network Automation Login" >< res) {
  # This probably could be checked with a single eregmatch(), however the correct regex is unclear
  lines = split(res);
  c = 0;

  foreach line(lines) {
    c++;
    vers = 'unknown';
    if ("Version:" >< line) {
       version = eregmatch(pattern: "<td>([^<]+)</td>", string: lines[c]);
       if (!isnull(version[1]))
         vers = version[1];
    }

    set_kb_item(name: string("www/", port, "/netmri"), value: string(vers," under /"));
    set_kb_item(name:"netMRI/detected", value:TRUE);

    cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:infoblox:netmri:");
    if (!cpe)
      cpe = 'cpe:/a:infoblox:netmri';

    register_product(cpe: cpe, location: "/", port: port, service: "www");

    log_message(data: build_detection_report(app: "Infoblox NetMRI", version: vers, install: "/", cpe: cpe,
                                             concluded: version[0]),
                port: port);

    exit(0);
  }
}

exit(0);
