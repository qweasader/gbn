# OpenVAS Vulnerability Test
# Description: Cheops NG without password
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
  script_oid("1.3.6.1.4.1.25623.1.0.20161");
  script_version("2022-05-31T13:27:00+0100");
  script_tag(name:"last_modification", value:"2022-05-31 13:27:00 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Cheops NG without password");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("General");
  script_dependencies("cheopsNG_detect.nasl");
  script_mandatory_keys("cheopsNG/unprotected");

  script_tag(name:"solution", value:"Restrict access to this port or enable authentication by starting the
  agent using the '-p' option.");

  script_tag(name:"summary", value:"The remote service does not require a password for access.");

  script_tag(name:"insight", value:"The Cheops NG agent on the remote host is running without
  authentication. Anyone can connect to this service and use it to map
  the network, port scan machines and identify running services.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item("cheopsNG/unprotected");
if(port)
  security_message(port:port);