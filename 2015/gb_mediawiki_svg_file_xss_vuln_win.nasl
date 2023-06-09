###############################################################################
# OpenVAS Vulnerability Test
#
# MediaWiki 'SVG File' Cross Site Scripting Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806634");
  script_version("2022-04-14T06:42:08+0000");
  script_cve_id("CVE-2014-7199");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-11-26 16:21:27 +0530 (Thu, 26 Nov 2015)");
  script_name("MediaWiki 'SVG File' Cross Site Scripting Vulnerability (Windows)");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in CSS
  filtering in SVG files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via a crafted SVG file.");

  script_tag(name:"affected", value:"MediaWiki before 1.19.19, 1.22.x before
  1.22.11, and 1.23.x before 1.23.4 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 1.19.19 or 1.22.11 or
  1.23.4 or later.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-September/000161.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70153");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "os_detection.nasl", "secpod_mediawiki_detect.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!http_ver = get_app_version(cpe:CPE, port:http_port)){
  exit(0);
}

if(version_is_less(version:http_ver, test_version:"1.19.19"))
{
  fix = "1.19.19";
  VULN = TRUE ;
}

else if(version_in_range(version:http_ver, test_version:"1.22.0", test_version2:"1.22.10"))
{
  fix = "1.22.11";
  VULN = TRUE ;
}

else if(version_in_range(version:http_ver, test_version:"1.23.0", test_version2:"1.23.3"))
{
  fix = "1.23.4";
  VULN = TRUE ;
}

if(VULN)
{
  report = 'Installed version: ' + http_ver + '\n' +
           'Fixed version:     ' + fix      + '\n';
  security_message(port:http_port, data:report);
  exit(0);
}

exit(99);