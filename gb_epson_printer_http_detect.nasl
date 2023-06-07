# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program;

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146411");
  script_version("2022-01-31T13:17:52+0000");
  script_tag(name:"last_modification", value:"2022-01-31 13:17:52 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"creation_date", value:"2021-08-02 05:20:20 +0000 (Mon, 02 Aug 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Epson Printer Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Epson printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  # nb: Don't use e.g. webmirror.nasl or DDI_Directory_Scanner.nasl as this VT should
  # run as early as possible so that the printer can be early marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("epson_printers.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

urls = get_epson_detect_urls();

foreach url (keys(urls)) {
  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");

  res = http_get_cache(port: port, item: url);
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  if (match = eregmatch(pattern: pattern, string: res, icase: TRUE)) {
    set_kb_item(name: "epson/printer/detected", value: TRUE);
    set_kb_item(name: "epson/printer/http/detected", value: TRUE);
    set_kb_item(name: "epson/printer/http/port", value: port);

    model = "unknown";
    fw_version = "unknown";

    if (!isnull(match[1])) {
      model = match[1];
      set_kb_item(name: "epson/printer/http/" + port + "/modConcluded", value: match[0]);
      set_kb_item(name: "epson/printer/http/" + port + "/modConcludedUrl",
                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    }

    url = "/PRESENTATION/ADVANCED/INFO_PRTINFO/TOP";
    res = http_get_cache(port: port, item: url);

    # >Firmware&nbsp;:</span></dt><dd class="value clearfix"><div class="preserve-white-space">07.57.LW26L2<
    vers = eregmatch(pattern: "Firmware[^-]+[^>]+>([^<]+)<", string: res);
    if (!isnull(vers[1])) {
      fw_version = vers[1];
      set_kb_item(name: "epson/printer/http/" + port + "/versConcluded", value: vers[0]);
      set_kb_item(name: "epson/printer/http/" + port + "/versConcludedUrl",
                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    } else {
      url = "/iPrinterHome.cgi";
      res = http_get_cache(port: port, item: url);

      # Main Version</td> <td height="16">02.20</td>
      vers = eregmatch(pattern: "Main Version</td>[^>]+>\s*([^<]+)<", string: res);
      if (!isnull(vers[1])) {
        fw_version = vers[1];
        set_kb_item(name: "epson/printer/http/" + port + "/versConcluded", value: vers[0]);
        set_kb_item(name: "epson/printer/http/" + port + "/versConcludedUrl",
                    value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
      }
    }

    set_kb_item(name: "epson/printer/http/" + port + "/model", value: model);
    set_kb_item(name: "epson/printer/http/" + port + "/fw_version", value: fw_version);

    exit(0);
  }
}

banner = http_get_remote_headers(port: port);

# e.g.:
# SERVER: EPSON_Linux UPnP/1.0 Epson UPnP SDK/1.0
# Server: EPSON HTTP Server
# Server: EPSON-HTTP/1.0
# nb: Note that the "Epson UPnP SDK" shouldn't use a "^"
# nb: Keep in sync with dont_print_on_printers.nasl and sw_http_os_detection.nasl
if (concl = egrep(pattern: "(^SERVER\s*:\s*(EPSON_Linux|EPSON HTTP Server|EPSON-HTTP)|Epson UPnP SDK)", string: banner, icase: TRUE)) {

  concl = chomp(concl);

  set_kb_item(name: "epson/printer/detected", value: TRUE);
  set_kb_item(name: "epson/printer/http/detected", value: TRUE);
  set_kb_item(name: "epson/printer/http/port", value: port);

  model = "unknown";
  fw_version = "unknown";
  hw_version = "unknown";

  set_kb_item(name: "epson/printer/http/" + port + "/model", value: model);
  set_kb_item(name: "epson/printer/http/" + port + "/fw_version", value: fw_version);
  set_kb_item(name: "epson/printer/http/" + port + "/hw_version", value: hw_version);
  set_kb_item(name: "epson/printer/http/" + port + "/generalConcluded", value: concl);
}

exit(0);
