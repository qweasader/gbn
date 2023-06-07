###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox 'data:' URI XSS Vulnerability - Sep09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800890");
  script_version("2022-03-01T14:58:37+0000");
  script_tag(name:"last_modification", value:"2022-03-01 14:58:37 +0000 (Tue, 01 Mar 2022)");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3012");
  script_name("Mozilla Firefox 'data:' URI XSS Vulnerability (Sep 2009) - Linux");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3323/");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3386/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct Cross-Site Scripting
  attacks in the victim's system.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.0.13 and prior, 3.5 and 3.6/3.7 a1 pre.");
  script_tag(name:"insight", value:"Firefox fails to sanitise the 'data:' URIs in Location headers in HTTP
  responses, which can be exploited via vectors related to injecting a Location
  header or Location HTTP response header.");
  script_tag(name:"solution", value:"Update to version 3.6.3 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less_equal(version:version, test_version:"3.0.13") ||
   version_is_equal(version:version, test_version:"3.5") ||
   version =~ "^3\.[67]a1pre") {
  report = report_fixed_ver(installed_version:version, fixed_version:"3.6.3", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
