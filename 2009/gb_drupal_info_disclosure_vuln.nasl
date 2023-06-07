###############################################################################
# OpenVAS Vulnerability Test
#
# Drupal Information Disclosure Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800909");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2374");
  script_name("Drupal Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://drupal.org/node/507572");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35548");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35657");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jul/1022497.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl");
  script_mandatory_keys("drupal/detected");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain that set of credentials which
  are included in the generated links.");

  script_tag(name:"affected", value:"Drupal Version 5.x before 5.19 and 6.x before 6.13 on all platforms.");

  script_tag(name:"insight", value:"Application fails to sanitize login attempts for pages that contain a sortable
  table, which includes the username and password in links that can be read from
  the HTTP referer header of external web sites that are visited from those links
  or when page caching is enabled, the Drupal page cache.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Drupal 5.19 or 6.13 or later.");

  script_tag(name:"summary", value:"Drupal is prone to an information disclosure vulnerability.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"5.0", test_version2:"5.18") ||
   version_in_range(version:version, test_version:"6.0", test_version2:"6.12")){
  report = report_fixed_ver(installed_version:version, fixed_version:"5.19/6.13", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);