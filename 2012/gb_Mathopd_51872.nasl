###############################################################################
# OpenVAS Vulnerability Test
#
# Mathopd Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103427");
  script_cve_id("CVE-2012-1050");
  script_version("2022-07-01T10:11:09+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Mathopd < 1.5p7 Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51872");
  script_xref(name:"URL", value:"http://www.mail-archive.com/mathopd%40mathopd.org/msg00392.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521507");

  script_tag(name:"last_modification", value:"2022-07-01 10:11:09 +0000 (Fri, 01 Jul 2022)");
  script_tag(name:"creation_date", value:"2012-02-16 15:14:41 +0100 (Thu, 16 Feb 2012)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Mathopd/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Mathopd is prone to a directory-traversal vulnerability because it
fails to sufficiently sanitize user-supplied input data.");

  script_tag(name:"impact", value:"Exploiting the issue may allow an attacker to obtain sensitive
information that could aid in further attacks.");

  script_tag(name:"affected", value:"Versions prior to Mathopd 1.5p7 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("version_func.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port: port);
if(!banner || "Server: Mathopd/" >!< banner)exit(0);

version = eregmatch(pattern:"Server: Mathopd/([0-9.p]+)",string:banner);
vers = version[1];

if(vers && "unknown" >!< vers) {

  if("p" >< vers) {
    vers1 = split(vers,sep:"p",keep:FALSE);
    if(!isnull(vers1[1])) {
      vers = vers1[0] + '.p' + vers1[1];
    }
  }

  if(version_is_less(version: vers, test_version: "1.5.p7")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
