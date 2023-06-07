# OpenVAS Vulnerability Test
# Description: Subversion Module File Restriction Bypass
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.13848");
  script_version("2023-05-11T09:09:33+0000");
  script_tag(name:"last_modification", value:"2023-05-11 09:09:33 +0000 (Thu, 11 May 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1438");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10800");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name:"OSVDB", value:"8239");
  script_name("Subversion < 1.0.6 Module File Restriction Bypass");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Remote file access");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/subversion");

  script_tag(name:"summary", value:"Subversion is prone to a flaw Apache module mod_authz_svn.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can access to any file in a given subversion
  repository, no matter what restrictions have been set by the administrator.");

  script_tag(name:"solution", value:"Update to version 1.0.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:3690, proto:"subversion");

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

r = recv_line(socket:soc, length:1024);
if(!r) {
  close(soc);
  exit(0);
}

dat = string("( 2 ( edit-pipeline ) 24:svn://host/svn/VT-Testr0x )");
send(socket:soc, data:dat);
r = recv_line(socket:soc, length:256);
close(soc);

if(!r)
  exit(0);

if(egrep(string:r, pattern:".*subversion-1\.0\.[0-5][^0-9].*")) {
  security_message(port:port);
  exit(0);
}

exit(99);
