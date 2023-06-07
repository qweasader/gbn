# OpenVAS Vulnerability Test
# Description: RaidenHTTPD directory traversal
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.16313");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12451");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("RaidenHTTPD < 1.1.31 Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("RaidenHTTPD/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"RaidenHTTPD is prone to a remote directory traversal
  vulnerability.");

  script_tag(name:"impact", value:"An attacker exploiting this flaw would be able to gain access to
  potentially confidential material outside of the web root.");

  script_tag(name:"solution", value:"Update to version 1.1.31 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("os_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
# Server: RaidenHTTPD/1.1.31 (Shareware)
if(! banner || "RaidenHTTP" >!< banner)
  exit(0);

files = traversal_files("windows");

foreach pattern(keys(files)) {

  file = files[pattern];

  if(http_vuln_check(port:port, url:file, pattern:pattern)) {
    report = http_report_vuln_url(port:port, url:file);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);