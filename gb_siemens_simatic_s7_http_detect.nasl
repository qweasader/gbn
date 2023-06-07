# Copyright (C) 2016 Greenbone Networks GmbH
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106098");
  script_version("2022-05-03T09:09:31+0000");
  script_tag(name:"last_modification", value:"2022-05-03 09:09:31 +0000 (Tue, 03 May 2022)");
  script_tag(name:"creation_date", value:"2016-06-15 17:03:46 +0700 (Wed, 15 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC S7 Device Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Siemens SIMATIC S7 devices like S7-300
  or S7-1200 PLCs.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/Portal/Portal.mwsl?PriNav=Ident";
req = http_get(item: url, port: port);
res = http_keepalive_send_recv(port: port, data: req);

# Seen on S7-1200
if ('alt="Siemens"'>< res && ('alt="Simatic Controller"></td>' >< res || 'Title_Area_Name">S7' >< res ||
                              "title>SIMATIC" >< res)) {

  set_kb_item(name: "siemens/simatic_s7/detected", value: TRUE);
  set_kb_item(name: "siemens/simatic_s7/http/detected", value: TRUE);
  set_kb_item(name: "siemens/simatic_s7/http/port", value: port);

  # nb: Newer firmware versions have the following in the title:
  # <title>S7-1200 station_1</title>
  # but this seems to be the "Station name" which can be changed and is thus currently not used for
  # identification.
  mod = eregmatch(pattern: "<title>SIMATIC\&nbsp;([A-Z]+)?([0-9]+).*<\/title>", string: res);
  if (!isnull(mod[2]))
    model = mod[2];

  version = "unknown";
  x = 0;
  lines = split(res);

  foreach line (lines) {
    if ("Firmware:" >< line ) {
      ver = eregmatch(pattern: ">V.([^<]+)<", string: lines[x+1]);
      if (!isnull(ver[1])) {
        version = ver[1];
        break;
      }
      else {
        ver = eregmatch(pattern: ">V.([^<]+)<", string: lines[x+5]);
        if (!isnull(ver[1])) {
          version = ver[1];
          break;
        }
      }
    }
    x++;
  }

  x = 0;
  foreach line (lines) {
    if ("Order number" >< line) {
      module = eregmatch(pattern: ">([^<]+)", string: lines[x+1]);
      if (!isnull(module[1])) {
        set_kb_item(name: "siemens/simatic_s7/http/module", value: module[1]);
        break;
      }
    }
    x++;
  }

  module_type = eregmatch(pattern: 'moduleType">([^<]+)', string: res);
  if (!isnull(module_type[1]))
    set_kb_item(name: "siemens/simatic_s7/http/modtype", value: module_type[1]);

  if (model)
    set_kb_item(name: "siemens/simatic_s7/http/model", value: model);

  if (version != "unknown")
    set_kb_item(name: "siemens/simatic_s7/http/" + port + "/version", value: version);
}

# Seen on S7-300
res = http_get_cache(item: "/", port: port);
if (!res || res !~ "^HTTP/1\.[01] 302" || res !~ "Location\s*:\s*/Portal0000\.htm")
  exit(0);

url = "/Portal0000.htm";
res = http_get_cache(item: url, port: port);
if (!res || res !~ "^HTTP/1\.[01] 200")
  exit(0);

# nb: Similar to the S7-1200 devices there a few have the default of:
# <title>
# SIMATIC 300
# </title>
# but this is again the "Station name" which can be changed / modified and thus not used for
# identification.
if ('href="/S7Web.css">' >< res ||
    'alt="Simatic S7 CP">' >< res ||
    'src="/Siemens_Firmenmarke_Header.gif" alt="Siemens"' >< res) {

  set_kb_item(name: "siemens/simatic_s7/detected", value: TRUE);
  set_kb_item(name: "siemens/simatic_s7/http/detected", value: TRUE);
  set_kb_item(name: "siemens/simatic_s7/http/port", value: port);

  # Module type is directly available on Portal0000.htm like e.g.:
  #
  # <td class="static_field">Module type:</td>
  # <td class="output_field_long">CP 343-1 Lean</td>
  #
  # or:
  #
  # <td class="static_field">Module type:</td>
  # <td class="output_field_long">CP 343-1</td>
  #
  mod_type = eregmatch(pattern: ">Module type:</td>[^/]+>(CP [^<]+)</td>", string: res);
  if (!isnull(mod_type[1])) {

    module_type = mod_type[1];

    # nb: Four spaces for the reporting in the consolidation...
    concluded = "    " + mod_type[0];
    concluded = "    " + str_replace( string:mod_type[0], find:'\r\n', replace:"newline-replaced" );
    concluded_url = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    set_kb_item(name: "siemens/simatic_s7/http/modtype", value: module_type);

    # The model / series wasn't available on at least S7-300 devices so we're grabbing it from the
    # module type (if available).
    if (module_type =~ "CP 15[0-9]+")
      model = "1500";
    else if (module_type =~ "CP 12[0-9]+")
      model = "1200";
    else if (module_type =~ "CP 4[0-9]+")
      model = "400";
    else if (module_type =~ "CP 3[0-9]+")
      model = "300";
    else if (module_type =~ "CP 2[0-9]+")
      model = "200";
  }

  version = "unknown";
  # Version needs to be grabbed from the Portal1000.htm (at least on the S7-300)
  url = "/Portal1000.htm";
  res = http_get_cache(item: url, port: port);
  if (res && res =~ "^HTTP/1\.[01] 200") {

    # e.g. on the S7-300:
    #
    # <td class="static_field">Firmware:</td>
    # <td class="output_field_long">V2.3.2</td>
    #
    # or:
    #
    # <td class="static_field">Firmware:</td>
    # <td class="output_field_long">V3.1.1</td>
    #
    vers = eregmatch(pattern: ">Firmware:</td>[^/]+>V([0-9.]+)[^<]*</td>", string: res);
    if (vers[1]) {

      version = vers[1];

      if (concluded)
        concluded += '\n';
      concluded += "    " + str_replace( string:vers[0], find:'\r\n', replace:"newline-replaced" );

      if (concluded_url)
        concluded_url += '\n';
      concluded_url += "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }
  }

  if (concluded)
    set_kb_item(name: "siemens/simatic_s7/http/" + port + "/concluded", value: concluded);

  if (concluded_url)
    set_kb_item(name: "siemens/simatic_s7/http/" + port + "/concludedurl", value: concluded_url);

  if (model)
    set_kb_item(name: "siemens/simatic_s7/http/model", value: model);

  if (version != "unknown")
    set_kb_item(name: "siemens/simatic_s7/http/" + port + "/version", value: version);
}

exit(0);
