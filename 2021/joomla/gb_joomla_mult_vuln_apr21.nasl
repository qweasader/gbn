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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145768");
  script_version("2021-08-24T09:01:06+0000");
  script_tag(name:"last_modification", value:"2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 09:06:32 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-22 00:35:00 +0000 (Thu, 22 Apr 2021)");

  script_cve_id("CVE-2021-26030", "CVE-2021-26031");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 3.0.0 - 3.9.25 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-26030: Inadequate escaping allows cross-site scripting (XSS) attacks using the logo
  parameter of the default templates on error pages.

  - CVE-2021-26031: Inadequate filters on module layout settings could lead to a
  local file inclusion (LFI).");

  script_tag(name:"affected", value:"Joomla! versions 3.0.0 through 3.9.25.");

  script_tag(name:"solution", value:"Update to version 3.9.26 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/850-20210401-core-escape-xss-in-logo-parameter-error-pages.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/851-20210402-core-inadequate-filters-on-module-layout-settings.html");

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

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.9.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.26", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
