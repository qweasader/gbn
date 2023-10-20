# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106322");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-10-04 13:39:10 +0700 (Tue, 04 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Avaya IP Office Detection");

  script_tag(name:"summary", value:"Detection of Avaya IP Office.

  The script sends a connection request to the server and attempts to detect the presence of Avaya IP Office and to
  extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://support.avaya.com/products/P0160/ip-office-platform");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/index.html");

if ("<title>About IP Office" >< res && "<o:Company>Avaya</o:Company>" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "Version: ([0-9.]+) \(([0-9]+)\)", string: res);
  if(!isnull(vers[1]) && !isnull(vers[2])) {
    version = vers[1] + '.' + vers[2];
  } else {
    # >IP Office R11.0.4.1<
    # >IP Office Select R10.0.0.3<
    vers = eregmatch(pattern: ">IP\s+Office (Select )?R([0-9.]+)<", string: res, icase: TRUE);
    if (!isnull(vers[2]))
      version = vers[2];
  }

  set_kb_item(name: "avaya/ip_office/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:avaya:ip_office:");
  if (!cpe)
    cpe = "cpe:/a:avaya:ip_office";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Avaya IP Office", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
