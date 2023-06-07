###############################################################################
# OpenVAS Vulnerability Test
#
# Joomla Component Inneradmission SQL Injection Vulnerability
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804272");
  script_version("2022-04-14T11:24:11+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-04-29 19:08:26 +0530 (Tue, 29 Apr 2014)");

  script_name("Joomla Component Inneradmission SQL Injection Vulnerability");

  script_tag(name:"summary", value:"Joomla! component Inneradmission is prone to a sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is possible
to execute a sql query.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation of 'id' HTTP GET parameter
passed to 'index.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary SQL
commands in applications database and gain complete control over the vulnerable web application.");

  script_tag(name:"affected", value:"Inneradmission Extension for Joomla");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126062");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66708");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!http_port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?option=com_inneradmission&id=1'a";

if (http_vuln_check(port:http_port, url:url, check_header:TRUE, pattern:"an error in your SQL syntax",
                    extra_check:make_list("id='1'a'", "com_inneradmission"))) {
  report = http_report_vuln_url(port: http_port, url: url);
  security_message(port: http_port, data: report);
  exit(0);
}

exit(99);
