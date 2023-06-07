###############################################################################
# OpenVAS Vulnerability Test
#
# Lexmark Printer Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103685");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-03-28 11:31:24 +0100 (Thu, 28 Mar 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Lexmark Printer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  # nb: Don't use e.g. webmirror.nasl or DDI_Directory_Scanner.nasl as this VT should
  # run as early as possible so that the printer can be early marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Lexmark printer devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("lexmark_printers.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default: 80);

urls = get_lexmark_detect_urls();

foreach url(keys(urls)) {

  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");

  buf = http_get_cache(item: url, port: port);
  if(!buf || buf !~ "^HTTP/1\.[01] 200")
    continue;

  if (lex = eregmatch(pattern: pattern, string: buf, icase: TRUE)) {

    if (!isnull(lex[1])) {

      concluded = '\n' + lex[0];
      concludedUrl = '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      model     = chomp(lex[1]);

      set_kb_item(name: "lexmark_printer/detected", value: TRUE);
      set_kb_item(name: "lexmark_printer/http/detected", value: TRUE);
      set_kb_item(name: "lexmark_printer/http/port", value: port);
      set_kb_item(name: "lexmark_printer/http/" + port + "/model", value: model);

      url = '/cgi-bin/dynamic/printer/config/reports/deviceinfo.html';
      headers = make_array("Cookie", "lexlang=0;"); # language should be english
      req = http_get_req(port: port, url: url, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      # >Base</p></td><td><p> =  LW63.GM2.P641-0 </p></td>
      vers = eregmatch(pattern: '>Base</p></td><td><p> =  ([^ ]+)', string: res);
      if (!isnull(vers[1])) {
        set_kb_item(name: "lexmark_printer/http/" + port + "/fw_version", value: vers[1]);
        concluded += '\n' + vers[0];
        concludedUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
      else {
        url = '/webglue/content?c=%2FStatus&lang=en';
        res = http_get_cache(port: port, item: url);

        vers = eregmatch(pattern: 'Firmware Level.*<span class="untranslated">([^<]+)', string: res);
        if (!isnull(vers[1])) {
          set_kb_item(name: "lexmark_printer/http/" + port + "/fw_version", value: vers[1]);
          concluded += '\n' + vers[0];
          concludedUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        }
      }

      set_kb_item(name: "lexmark_printer/http/" + port + "/concluded", value: concluded);
      set_kb_item(name: "lexmark_printer/http/" + port + "/concludedUrl", value: concludedUrl);

      exit(0);
    }
  }
}

exit(0);
