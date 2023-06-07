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
  script_oid("1.3.6.1.4.1.25623.1.0.106346");
  script_version("2023-01-18T10:11:02+0000");
  script_tag(name:"last_modification", value:"2023-01-18 10:11:02 +0000 (Wed, 18 Jan 2023)");
  script_tag(name:"creation_date", value:"2016-10-12 11:13:38 +0700 (Wed, 12 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MatrixSSL Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of MatrixSSL.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("MatrixSSL/banner");

  script_xref(name:"URL", value:"http://www.matrixssl.org");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

banner = http_get_remote_headers(port: port);

if (concl = egrep(string: banner, pattern: "^Server\s*: .*MatrixSSL", icase: TRUE)) {

  concl = chomp(concl);
  version = "unknown";

  vers = eregmatch(pattern: "MatrixSSL\/([0-9.]+)", string: banner);
  if (!isnull(vers[1])) {
    version = vers[1];
    concl = vers[0];
  }

  set_kb_item(name: "matrixssl/detected", value: TRUE);
  set_kb_item(name: "matrixssl/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:matrixssl:matrixssl:");
  if (!cpe)
    cpe = "cpe:/a:matrixssl:matrixssl";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "MatrixSSL", version: version, install: "/", cpe: cpe,
                                           concluded: concl),
              port: port);
}

exit(0);
