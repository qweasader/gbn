###############################################################################
# OpenVAS Vulnerability Test
#
# OpenCart Multiple Vulnerabilities Dec-13
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:opencart:opencart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804161");
  script_version("2022-04-25T14:50:49+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-12-09 19:52:35 +0530 (Mon, 09 Dec 2013)");

  script_name("OpenCart Multiple Vulnerabilities Dec-13");

  script_tag(name:"summary", value:"OpenCart is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is vulnerable
or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"The flaws are due to:

  - Input passed via the 'zone_id' POST parameter to index.php is not properly sanitised before being returned to
    the user.

  - Insufficient authorization accessing 'system/logs/error.txt' which displays the full installation path within
    error messages.

  - Insufficient validity checks to verify the HTTP requests made by user.");

  script_tag(name:"affected", value:"OpenCart version 1.5.6 and probably previous versions may also be affected.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary
HTML or script code, discloses the software's installation path resulting in a loss of confidentiality.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53036");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64162");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Dec/29");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/53036");
  script_xref(name:"URL", value:"http://www.garda.ir/Opencart_Multiple_Vulnerabilities.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("opencart_detect.nasl");
  script_mandatory_keys("OpenCart/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/system/logs/error.txt";

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"PHP Notice:  Undefined index:")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
