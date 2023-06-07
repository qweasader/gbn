# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:woocommerce:woocommerce";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112909");
  script_version("2022-07-20T10:33:02+0000");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2021-07-16 11:00:00 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-04 19:49:00 +0000 (Wed, 04 Aug 2021)");

  script_cve_id("CVE-2021-32790");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WooCommerce Plugin SQL Injection Vulnerability (Jul 2021) - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woocommerce/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WooCommerce' is prone to an SQL
  injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Malicious actors (already) having admin access, or API keys to
  the WooCommerce site can exploit vulnerable endpoints of /wp-json/wc/v3/webhooks,
  /wp-json/wc/v2/webhooks and other webhook listing API. Read-only SQL queries can be executed using
  this exploit, while data will not be returned, by carefully crafting search parameter information
  can be disclosed using timing and related attacks.");

  script_tag(name:"impact", value:"The vulnerability allows authenticated attackers to access
  arbitrary data in an online store's database.");

  script_tag(name:"affected", value:"The vulnerability affects versions 3.3 to 5.5.");

  script_tag(name:"solution", value:"Updates are available. Please see the referenced advisory
  for more information.");

  script_xref(name:"URL", value:"https://woocommerce.com/posts/critical-vulnerability-detected-july-2021/#");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/07/critical-sql-injection-vulnerability-patched-in-woocommerce/");
  script_xref(name:"URL", value:"https://viblo.asia/p/phan-tich-loi-unauthen-sql-injection-woocommerce-naQZRQyQKvx");
  script_xref(name:"URL", value:"https://github.com/woocommerce/woocommerce/security/advisories/GHSA-7vx5-x39w-q24g");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.4.0", test_version2: "3.4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.5.0", test_version2: "3.5.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.6.0", test_version2: "3.6.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.7.0", test_version2: "3.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.8.0", test_version2: "3.8.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.9.0", test_version2: "3.9.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.1.0", test_version2: "4.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.2.0", test_version2: "4.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.0", test_version2: "4.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4.0", test_version2: "4.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.5.0", test_version2: "4.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.6.0", test_version2: "4.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.7.0", test_version2: "4.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.8.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.9.0", test_version2: "4.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.4.0", test_version2: "5.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
