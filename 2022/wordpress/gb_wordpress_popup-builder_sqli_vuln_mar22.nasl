# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:sygnoos:popup_builder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124050");
  script_version("2022-07-19T10:11:08+0000");
  script_tag(name:"last_modification", value:"2022-07-19 10:11:08 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-04-01 14:29:45 +0000 (Fri, 01 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 16:19:00 +0000 (Mon, 04 Apr 2022)");

  script_cve_id("CVE-2022-0479");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Popup Builder Plugin < 4.1.1 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/popup-builder/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Popup Builder' is prone to an
  authenticated SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Popup Builder WordPress plugin does not sanitise and escape
  the sgpb-subscription-popup-id parameter before using it in a SQL statement
  in the All Subscribers admin dashboard, leading to an SQL injection, which could also be used
  to perform Reflected Cross-Site Scripting attack against a logged in admin opening a
   malicious link");

  script_tag(name:"affected", value:"WordPress Popup Builder plugin prior to version 4.1.1.");

  script_tag(name:"solution", value:"Update to version 4.1.1 or later.");

  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/changeset/2686454");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/0d2bbbaf-fbfd-4921-ba4e-684e2e77e816");

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

if (version_is_less(version: version, test_version: "4.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
