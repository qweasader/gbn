###############################################################################
# OpenVAS Vulnerability Test
#
# Detect SWAT server port
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Modifications by Renaud Deraison
#
# Copyright:
# Copyright (C) 2005 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10273");
  script_version("2020-11-10T15:30:28+0000");
  script_tag(name:"last_modification", value:"2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Detect SWAT server port");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/swat", 901);

  script_tag(name:"summary", value:"SWAT (Samba Web Administration Tool) is running on this port.

  SWAT allows Samba users to change their passwords, and offers to the sysadmin
  an easy-to-use GUI to configure Samba.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = service_get_port(proto:"swat", default:1);
if(port==1){
  nosvc = 1;
  port = 901;
}

if (get_port_state(port))
{
 soctcp901 = http_open_socket(port);

 if (soctcp901)
 {
  sendata = http_get(item:"/", port:port);
  send(socket:soctcp901, data:sendata);
  banner = http_recv(socket:soctcp901);
  quote = raw_string(0x22);

  expect = "WWW-Authenticate: Basic realm=" + quote + "SWAT" + quote;

  if (expect >< banner)
  {
    if ( nosvc ) service_register(proto:"swat", port:port);
  }
  http_close_socket(soctcp901);
 }
}
