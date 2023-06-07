# OpenVAS Vulnerability Test
# Description: Cisco bug ID CSCdu35577 (Web Check)
#
# Authors:
# Michael J. Richardson <michael.richardson@protiviti.com>
#
# Copyright:
# Copyright (C) 2004 Michael J. Richardson
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
  script_oid("1.3.6.1.4.1.25623.1.0.14718");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1094");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Cisco bug ID CSCdu35577 (Web Check)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Michael J. Richardson");
  script_family("CISCO");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.cisco.com/warp/public/707/vpn3k-multiple-vuln-pub.shtml");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5624");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"The remote VPN concentrator gives out too much information in application
  layer banners.

  An incorrect page request provides the specific version of software installed.

  This vulnerability is documented as Cisco bug ID CSCdu35577.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
req = http_get(item:"/this_page_should_not_exist.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!res)
  exit(0);

if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) && "<b>Software Version:</b> >< res" && "Cisco Systems, Inc./VPN 3000 Concentrator Version" >< res) {
  report = "The following software version was identified: " + egrep(pattern:"Cisco Systems, Inc./VPN 3000 Concentrator Version", string:res);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
