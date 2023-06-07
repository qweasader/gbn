# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140167");
  script_version("2022-07-11T10:16:03+0000");
  script_tag(name:"last_modification", value:"2022-07-11 10:16:03 +0000 (Mon, 11 Jul 2022)");
  script_tag(name:"creation_date", value:"2017-02-17 16:32:23 +0100 (Fri, 17 Feb 2017)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("MQTT Broker Does Not Require Authentication");

  script_category(ACT_GATHER_INFO);

  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_mqtt_detect.nasl");
  script_require_ports("Services/mqtt", 1883);
  script_mandatory_keys("mqtt/no_user_pass");

  script_tag(name:"summary", value:"The remote MQTT broker does not require authentication.");

  script_tag(name:"vuldetect", value:"Checks if authentication is required for the remote MQTT
  broker.");

  script_tag(name:"solution", value:"Enable authentication.");

  script_xref(name:"URL", value:"https://www.heise.de/newsticker/meldung/MQTT-Protokoll-IoT-Kommunikation-von-Reaktoren-und-Gefaengnissen-oeffentlich-einsehbar-3629650.html");

  exit(0);
}

include("port_service_func.inc");

if( ! port = service_get_port( default:1883, proto:"mqtt" ) )
  exit( 0 );

if( ! get_kb_item( "mqtt/" + port + "/no_user_pass" ) )
  exit( 99 );

security_message( port:port );
exit( 0 );