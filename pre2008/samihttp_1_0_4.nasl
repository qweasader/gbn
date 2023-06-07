# OpenVAS Vulnerability Test
# Description: Sami HTTP Server v1.0.4
#
# Authors:
# Audun Larsen <larsen@xqus.com>
# Based on Apache < 1.3.27 written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2004 Audun Larsen
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
  script_oid("1.3.6.1.4.1.25623.1.0.12073");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0292");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9679");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Sami HTTP Server v1.0.4");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Audun Larsen");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Sami_HTTP/banner");

  script_tag(name:"solution", value:"Upgrade Sami HTTP when an upgrade becomes available.");

  script_tag(name:"summary", value:"The remote host seems to be running Sami HTTP Server v1.0.4 or older.

  A vulnerability has been reported for Sami HTTP server v1.0.4.");

  script_tag(name:"impact", value:"An attacker may be capable of corrupting data such as return address,
  and thereby control the execution flow of the program.
  This may result in denial of service or execution of arbitrary code.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port: port);
if(!banner || "Sami HTTP Server" >!< banner)
  exit(0);

if(egrep(pattern:"Server:.*Sami HTTP Server v(0\.|1\.0\.[0-4][^0-9])", string:banner) ) {
  security_message(port:port);
  exit(0);
}

exit(99);
