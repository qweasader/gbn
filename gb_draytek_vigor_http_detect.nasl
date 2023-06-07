# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143661");
  script_version("2022-08-08T10:24:51+0000");
  script_tag(name:"last_modification", value:"2022-08-08 10:24:51 +0000 (Mon, 08 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-03-31 08:28:25 +0000 (Tue, 31 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DrayTek Vigor Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of DrayTek Vigor devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

fingerprint["6749372bdea55e2ff3c5f631c13e945f"] = "165";
fingerprint["bab52c2d280cc70bc4a1d3b7ac4bc4c8"] = "2120";
fingerprint["4f03017fc1432854ddaec16738e6c7f6"] = "2133";
fingerprint["1d61282d0995f0b63b28840448ff31d7"] = "2620";
fingerprint["4172705528245ca522368b8a75a06ac1"] = "2760";
fingerprint["b05c6d98c3118430f9c3be10a22681fa"] = "2762";
fingerprint["5f3959c010e8e7cc04b0c0f206935e90"] = "2765";
fingerprint["eab44a2839f45dfbe95d6d89c5df491b"] = "2832";
fingerprint["75c151788f32d1f4a61400b2248453b0"] = "2860";
fingerprint["7e569db3f217067016a29aa245fd2332"] = "2862";
fingerprint["7b562c87d45cabc36591098777962cf5"] = "2865";
fingerprint["21f8e1de0330aa67d602bf18000bb2eb"] = "2865"; # nb: On weblogin.png
fingerprint["593a9bb0503491870ff4ed8ee39e490c"] = "2912";
fingerprint["1f187cf87c5c57c043e259e0401dc90a"] = "2915";
fingerprint["f530aff4ad44eb41667d9638dfcf2041"] = "2925";
fingerprint["cd9845ab5f472db67f569b7167c4ddc0"] = "2952";
fingerprint["08b1c6970d62ffba7397bd50e757c4c9"] = "3220";

port = http_get_port(default: 443);

url = "/";
res = http_get_cache(port: port, item: url);
url2 = "/weblogin.htm";
res2 = http_get_cache(port: port, item: url2);

# Server: DrayTek/Vigor2130 UPnP/1.0 miniupnpd/1.0
if (("<title>Vigor " >< res && "isomorphicDir" >< res && res =~ "Server\s*:\s*DWS") ||
     ("<title>Vigor Login Page</title>" >< res2 && "DrayTek" >< res2) || res =~ "Server\s*:\s*DrayTek/Vigor") {
  model = "unknown";
  version = "unknown";

  set_kb_item(name: "draytek/vigor/detected", value: TRUE);
  set_kb_item(name: "draytek/vigor/http/detected", value: TRUE);
  set_kb_item(name: "draytek/vigor/http/port", value: port);

  mod = eregmatch(pattern: "<title>Vigor ([0-9A-Z]+)", string: res);
  if (!isnull(mod[1]) && "Vigor Login Page" >!< res) {
    model = mod[1];
    set_kb_item(name: "draytek/vigor/http/" + port + "/concluded", value: mod[0]);
    set_kb_item(name: "draytek/vigor/http/" + port + "/concludedUrl", value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
  }

  if (model == "unknown") {
    mod = eregmatch(pattern: "Server\s*:\s*DrayTek/Vigor([0-9A-Z]+)", string: res);
    if (!isnull(mod[1])) {
      model = mod[1];
      set_kb_item(name: "draytek/vigor/http/" + port + "/concluded", value: mod[0]);
      set_kb_item(name: "draytek/vigor/http/" + port + "/concludedUrl", value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    }
  }

  if (model == "unknown") {
    # >Vigor 3910<
    # >Vigor1000B<
    mod = eregmatch(pattern: ">Vigor\s*([0-9A-Z]+)<", string: res2);
    if (!isnull(mod[1])) {
      model = mod[1];
      set_kb_item(name: "draytek/vigor/http/" + port + "/concluded", value: mod[0]);
      set_kb_item(name: "draytek/vigor/http/" + port + "/concludedUrl", value: http_report_vuln_url(port: port, url: url2, url_only: TRUE));
    }
  }

  if (model == "unknown") {
    foreach url (make_list("/images/login.png", "/images/login1.png", "/images/weblogin.png")) {
      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);
      if(res) {
        md5 = hexstr(MD5(res));
        fp = fingerprint[md5];
        if (fp) {
          model = fp;
          set_kb_item(name: "draytek/vigor/http/" + port + "/concludedUrl", value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
          break;
        }
      }
    }
  }

  set_kb_item(name: "draytek/vigor/http/" + port + "/model", value: model);
  set_kb_item(name: "draytek/vigor/http/" + port + "/version", value: version);
}

exit(0);
