###############################################################################
# OpenVAS Vulnerability Test
#
# LIVE555 Streaming Media Server Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.107180");
  script_version("2020-11-10T09:46:51+0000");
  script_tag(name:"last_modification", value:"2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-05-22 12:42:40 +0200 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("LIVE555 Streaming Media Server Detection (RTSP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 554, 8554);

  script_tag(name:"summary", value:"Detection of the installed version of LIVE555 Streaming Media Server.

  The script detects the version of LIVE555 Streaming Media Server on the remote host via RSTP banner,
  to extract the version number and to set the KB entries.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(proto: "rtsp", default: 8554);

if (!banner = get_kb_item("RTSP/" + port + "/server_banner"))
  if(!banner = get_kb_item("www/banner/" + port))
    exit( 0 );

if (banner =~ "Server: LIVE555") {
  version = "unknown";

  set_kb_item(name: "live555/streaming_media/detected", value: TRUE);
  set_kb_item(name: "live555/streaming_media/rtsp/port", value: port);
  set_kb_item(name: "live555/streaming_media/rtsp/" + port + "/concluded", value: banner);

  vers = eregmatch(pattern: "LIVE555 Streaming Media v([0-9.]+)", string: banner);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "live555/streaming_media/rtsp/" + port + "/version", value: version);
}

exit(0);
