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

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117734");
  script_version("2021-10-25T08:03:40+0000");
  script_tag(name:"last_modification", value:"2021-10-25 08:03:40 +0000 (Mon, 25 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-18 14:24:02 +0000 (Mon, 18 Oct 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-21 16:45:00 +0000 (Thu, 21 Oct 2021)");

  script_cve_id("CVE-2021-36097");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Permission Bypass Vulnerability (OSA-2021-20)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to a permission bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Agents are able to lock the ticket without the 'Owner'
  permission. Once the ticket is locked, it could be moved to the queue where the agent has 'rw'
  permissions and gain a full control.");

  script_tag(name:"affected", value:"OTRS version 8.0.x through 8.0.16.");

  script_tag(name:"solution", value:"Update to version 8.0.17 or later.");

  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2021-20/");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);