# Copyright (C) 2005 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:photopost:photopost_php_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16101");
  script_version("2022-07-26T10:10:42+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:42 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2005-0273", "CVE-2005-0274");
  script_xref(name:"OSVDB", value:"12741");
  script_xref(name:"OSVDB", value:"12742");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PhotoPost SQLi Vulnerability (Nov 2005) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("photopost_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("photopost/http/detected");

  script_tag(name:"summary", value:"PhotoPost PHP contains a vulnerability in the file
  'showgallery.php' which allows a remote attacker to cause the program to execute arbitrary SQL
  statements against the remote database.");

  script_tag(name:"solution", value:"Upgrade to the newest version of this software.");

  script_xref(name:"URL", value:"http://www.gulftech.org/?node=research&article_id=00063-01032005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12156");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12157");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/showgallery.php?cat=1'";

if (http_vuln_check(port: port, url: url, pattern: "SELECT id,catname,description,photos")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
