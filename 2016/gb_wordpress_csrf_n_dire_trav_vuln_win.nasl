###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Core Ajax handlers CSRF and Directory Traversal Vulnerabilities (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809156");
  script_version("2023-03-01T10:20:05+0000");
  script_cve_id("CVE-2016-6896", "CVE-2016-6897", "CVE-2016-10148");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:05 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-03 01:29:00 +0000 (Sun, 03 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-08-26 14:01:02 +0530 (Fri, 26 Aug 2016)");
  script_name("WordPress Core Ajax handlers CSRF and Directory Traversal Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"WordPress is prone to CSRF and directory traversal vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper capability
  check in 'wp_ajax_update_plugin' and 'wp_ajax_delete_plugin' functions
  which are used in 'ajax-actions.php' script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  attacker to take over an authenticated user's session (privilege escalation)
  using a forged HTML page and to crash the web server.");

  script_tag(name:"affected", value:"WordPress version 4.5.3 on Windows.");

  script_tag(name:"solution", value:"Update to WordPress version 4.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40288/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92573");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92572");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wpPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!wpVer = get_app_version(cpe:CPE, port:wpPort)){
  exit(0);
}

if(version_is_equal(version:wpVer, test_version:"4.5.3"))
{
  report = report_fixed_ver(installed_version:wpVer, fixed_version:"4.6");
  security_message(data:report, port:wpPort);
  exit(0);
}
