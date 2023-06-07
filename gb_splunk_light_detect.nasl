###############################################################################
# OpenVAS Vulnerability Test
#
# Splunk Light Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809012");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-08-26 17:00:30 +0530 (Fri, 26 Aug 2016)");
  script_name("Splunk Light Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Splunk Light.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:8000);

foreach dir (make_list_unique("/", "/splunk/en-US", "/en-US", http_cgi_dirs(port:port))) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache(item:dir + "/account/login", port:port);

  if(egrep(pattern:'content="Splunk Inc."', string: buf, icase: TRUE) &&
     ('Splunk Light' >< buf || 'product_type":"lite' >< buf)) {

    vers = string("unknown");

    version = eregmatch(string:buf, pattern:'version":"([0-9.]+)', icase:TRUE);

    if(!isnull(version[1])){
      vers = chomp(version[1]);
    } else {
      version = eregmatch(string:buf, pattern:'versionNumber": "([0-9.]+)', icase:TRUE);
      if(!isnull(version[1]))
        vers = chomp(version[1]);
    }

    b = eregmatch(string:buf, pattern:'build":"([0-9a-z.]+)', icase:TRUE);

    if(!isnull(b[1])){
      build = b[1];
    }

    set_kb_item(name: string("www/", port, "/splunklight"), value: string(vers));

    if(!isnull(build)){
      set_kb_item(name: string("www/", port, "/splunklight/build"), value: string(build));
    }

    set_kb_item(name:"SplunkLight/installed", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:splunk:light:");
    if(!cpe){
      cpe = "cpe:/a:splunk:light";
    }

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data: build_detection_report(app: "Splunk Light",
                                             version: vers,
                                             install: install,
                                             cpe: cpe,
                                             concluded: string(vers)), port: port);
    exit(0);
  }
}
