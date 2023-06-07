# OpenVAS Vulnerability Test
# Description: Cheops NG clear text authentication
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20162");
  script_version("2020-09-30T09:30:12+0000");
  script_tag(name:"last_modification", value:"2020-09-30 09:30:12 +0000 (Wed, 30 Sep 2020)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_name("Cheops NG clear text authentication");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("General");
  script_dependencies("cheopsNG_detect.nasl");
  script_mandatory_keys("cheopsNG/password");

  script_tag(name:"solution", value:"Configure Cheops to run on top of SSL or block this port
  from outside communication if you want to further restrict the use of Cheops.");

  script_tag(name:"summary", value:"A Cheops NG agent is running on the remote host.

  Users with a valid account on this machine can connect
  to this service and use it to map the network, port scan
  machines and identify running services.

  Passwords are transmitted in clear text and could be sniffed.
  More, using this Cheops agent, it is possible to brute force
  login/passwords on this system.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

port = get_kb_item("cheopsNG/password");
if(port && get_port_transport(port) == ENCAPS_IP ) {
  security_message(port:port);
  exit(0);
}

exit(99);
