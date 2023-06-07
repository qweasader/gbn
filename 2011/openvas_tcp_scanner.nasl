###############################################################################
# OpenVAS Vulnerability Test
#
# Wrapper for calling built-in NVT "openvas_tcp_scanner" which was previously
# a binary ".nes".
#
# Authors:
# Jan-Oliver Wagner <Jan-Oliver.Wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10335");
  script_version("2021-03-23T06:51:29+0000");
  script_tag(name:"last_modification", value:"2021-03-23 06:51:29 +0000 (Tue, 23 Mar 2021)");
  script_tag(name:"creation_date", value:"2011-01-14 10:12:23 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenVAS TCP scanner");
  script_category(ACT_SCANNER);
  script_family("Port scanners");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("host_alive_detection.nasl");

  script_timeout(4*360);

  script_tag(name:"summary", value:"This plugin is a classical TCP port scanner.
It shall be reasonably quick even against a firewalled target.

Once a TCP connection is open, it grabs any available banner
for the service identification plugins

Note that TCP scanners are more intrusive than
SYN (half open) scanners.");

  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

plugin_run_openvas_tcp_scanner();
