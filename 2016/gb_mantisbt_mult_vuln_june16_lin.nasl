# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808209");
  script_version("2022-03-15T08:15:23+0000");
  script_cve_id("CVE-2014-9759");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-15 08:15:23 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:02:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-06-03 17:28:33 +0530 (Fri, 03 Jun 2016)");

  script_name("MantisBT 1.3.x < 1.3.0-rc.2 SOAP API Information Disclosure Vulnerability - Linux");

  script_tag(name:"summary", value:"MantisBT is prone to an incomplete blacklist vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an incomplete blacklist
  vulnerability in the config_is_private function in 'config_api.php script' .
  When a new config is added or an existing one is renamed, the black list must
  be updated accordingly. If this is not or incorrectly done, the
  config becomes available via SOAP API");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to obtain sensitive master salt configuration information via a SOAP API request.");

  script_tag(name:"affected", value:"MantisBT versions 1.3.x before 1.3.0-rc.2.");

  script_tag(name:"solution", value:"Update to version 1.3.0-rc.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/01/02/1");
  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=20277");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_unixoide");

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

if (version_is_equal(version: version, test_version: "1.3.0-beta.1") ||
    version_is_equal(version: version, test_version: "1.3.0-beta.2") ||
    version_is_equal(version: version, test_version: "1.3.0-beta.3") ||
    version_is_equal(version: version, test_version: "1.3.0-rc.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.0-rc.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
