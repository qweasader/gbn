###############################################################################
# OpenVAS Vulnerability Test
#
# Splunk Enterprise libarchive Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:splunk:splunk';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106567");
  script_version("2022-05-31T14:25:35+0100");
  script_tag(name:"last_modification", value:"2022-05-31 14:25:35 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2017-02-06 11:21:45 +0700 (Mon, 06 Feb 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Enterprise libarchive Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_detect.nasl");
  script_mandatory_keys("Splunk/installed");

  script_tag(name:"summary", value:"Splunk Enterprise is prone to multiple vulnerabilities in libarchive.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple Vulnerabilities in libarchive addressed by version upgrade to
v3.2.2.");

  script_tag(name:"affected", value:"Splunk Enterprise 5.0.x, 6.0.x, 6.1.x, 6.2.x, 6.3.x, 6.4.x and 6.5.0");

  script_tag(name:"solution", value:"Update to version 5.0.17, 6.0.13, 6.1.12, 6.2.13, 6.3.9, 6.4.5, 6.5.1 or
later.");

  script_xref(name:"URL", value:"http://www.splunk.com/view/SP-CAAAPW8");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^5\.0") {
  if (version_is_less(version: version, test_version: "5.0.17")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.0.17");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.0") {
  if (version_is_less(version: version, test_version: "6.0.13")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.0.13");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.1") {
  if (version_is_less(version: version, test_version: "6.1.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.1.12");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.2") {
  if (version_is_less(version: version, test_version: "6.2.13")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.2.13");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.3") {
  if (version_is_less(version: version, test_version: "6.3.9")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.3.9");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.4") {
  if (version_is_less(version: version, test_version: "6.4.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.4.5");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.5") {
  if (version_is_less(version: version, test_version: "6.5.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.5.1");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
