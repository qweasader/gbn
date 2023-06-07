###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Multi View Event Calendar SQL Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804870");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2014-10-28 12:09:33 +0530 (Tue, 28 Oct 2014)");
  script_cve_id("CVE-2014-8586");

  script_name("WordPress Multi View Event Calendar SQL Injection Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'Multi View Event Calendar' is prone to sql-injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Input passed via the 'calid' GET parameter
  is not properly sanitized before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to
  manipulate SQL queries in the backend database allowing for the manipulation or
  disclosure of arbitrary data.");

  script_tag(name:"affected", value:"CP Multi View Event Calendar version 1.01");

  script_tag(name:"solution", value:"No known solution was made available for
  at least one year since the disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_active");

  script_xref(name:"URL", value:"http://1337day.com/exploits/22786");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35073/");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128814");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + '/?cpmvc_id=1&cpmvc_do_action=mvparse&f=datafeed&method=list&cal' +
            'id=1"SQLInjectionTest';

if(http_vuln_check(port:port, url:url, check_header:FALSE,
   pattern:"You have an error in your SQL syntax.*SQLInjectionTest"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}
