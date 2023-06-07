##############################################################################
# OpenVAS Vulnerability Test
#
# Joomla! 'Aclassif' Component Cross Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803089");
  script_version("2022-02-15T13:40:32+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-02-15 13:40:32 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2012-12-31 13:14:48 +0530 (Mon, 31 Dec 2012)");

  script_name("Joomla! 'Aclassif' Component Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80856");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/119108/Joomla-Aclassif-Cross-Site-Scripting.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
and script code, which will be executed in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Joomla! Aclassif Component");

  script_tag(name:"insight", value:"The flaw is due to an input passed to 'index.php/component/aclassif' is not
properly sanitised before it is returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Joomla! Aclassif component is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/index.php/component/aclassif/?"--></style></script><script>alert(3333)</script>';

if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern: "</script><script>alert\(3333\)</script>",
                    extra_check: "option=com_aclassif")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
