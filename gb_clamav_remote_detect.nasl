# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100651");
  script_version("2022-03-01T12:03:40+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-01 12:03:40 +0000 (Tue, 01 Mar 2022)");
  script_tag(name:"creation_date", value:"2015-06-17 14:03:59 +0530 (Wed, 17 Jun 2015)");
  script_name("ClamAV Detection (Remote)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/clamd", 3310);

  script_tag(name:"summary", value:"Remote detection of ClamAV.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");
include("port_service_func.inc");

port = service_get_port(default:3310, proto:"clamd");

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

req = string("VERSION\r\n");
send(socket:soc, data:req);
buf = recv(socket:soc, length:256);
close(soc);

if(!buf || "clamav" >!< tolower(buf))
  exit(0);

install = port + "/tcp";
version = "unknown";

# ClamAV 0.97.5
# ClamAV 0.100.3/25513/Wed Jul 17 08:15:42 2019
vers = eregmatch(pattern:"clamav ([0-9.]+)", string:tolower(buf));
if(vers[1])
  version = vers[1];

set_kb_item(name:"clamav/detected", value:TRUE);
set_kb_item(name:"clamav/remote/detected", value:TRUE);

cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:clamav:clamav:");
if(!cpe)
  cpe = "cpe:/a:clamav:clamav";

service_register(port:port, proto:"clamd");

register_product(cpe:cpe, location:install, port:port, service:"clamd");

log_message(data:build_detection_report(app:"ClamAV",
                                        version:version,
                                        install:install,
                                        cpe:cpe,
                                        concluded:vers[0]),
            port:port);
exit(0);
