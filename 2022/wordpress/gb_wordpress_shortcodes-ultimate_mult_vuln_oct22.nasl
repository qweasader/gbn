# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:getshortcodes:shortcodes_ultimate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127248");
  script_version("2022-11-11T10:10:59+0000");
  script_tag(name:"last_modification", value:"2022-11-11 10:10:59 +0000 (Fri, 11 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-10 11:01:55 +0000 (Thu, 10 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2022-38086", "CVE-2022-41136");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Shortcodes Ultimate Plugin < 5.12.1 Multiple CSRF Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/shortcodes-ultimate/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Shortcodes Ultimate' is prone to multiple
  cross-site request forgery (CSRF) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-38086: Cross-Site Request Forgery (CSRF) vulnerability leading to plugin preset
   settings change.

  - CVE-2022-41136: Cross-Site Request Forgery (CSRF) vulnerability leading to Stored Cross-Site
  Scripting (XSS).");

  script_tag(name:"affected", value:"WordPress Shortcodes Ultimate plugin prior to version 5.12.1.");

  script_tag(name:"solution", value:"Update to version 5.12.1 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/shortcodes-ultimate/wordpress-shortcodes-ultimate-plugin-5-12-0-cross-site-request-forgery-csrf-vulnerability?_s_id=cve");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/shortcodes-ultimate/wordpress-shortcodes-ultimate-plugin-5-12-0-csrf-vulnerability-leading-to-stored-xss?_s_id=cve");

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

if (version_is_less(version: version, test_version: "5.12.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.12.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
