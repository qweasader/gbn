# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:icegram:email_subscribers_%26_newsletters";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144571");
  script_version("2022-07-19T10:11:08+0000");
  script_tag(name:"last_modification", value:"2022-07-19 10:11:08 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"creation_date", value:"2020-09-14 07:10:03 +0000 (Mon, 14 Sep 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-16 14:37:00 +0000 (Wed, 16 Sep 2020)");

  script_cve_id("CVE-2020-5780");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Email Subscribers Plugin < 4.5.6 Email Forgery Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/email-subscribers/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Email Subscribers & Newsletters' is prone
  to an email forgery/spoofing vulnerability.");

  script_tag(name:"insight", value:"Missing Authentication for Critical Function in Icegram Email
  Subscribers & Newsletters Plugin for WordPress allows a remote, unauthenticated attacker to
  conduct unauthenticated email forgery/spoofing.");

  script_tag(name:"affected", value:"WordPress Email Subscribers & Newsletters plugin before
  version 4.5.6.");

  script_tag(name:"solution", value:"Update to version 4.5.6 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/email-subscribers/#developers");
  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2020-53");

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

if (version_is_less(version: version, test_version: "4.5.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
