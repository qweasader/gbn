###############################################################################
# OpenVAS Vulnerability Test
#
# Splunk Light XSS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/a:splunk:light';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106268");
  script_version("2022-05-31T13:22:01+0100");
  script_tag(name:"last_modification", value:"2022-05-31 13:22:01 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2016-09-19 11:58:34 +0700 (Mon, 19 Sep 2016)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Light XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_light_detect.nasl");
  script_mandatory_keys("SplunkLight/installed");

  script_tag(name:"summary", value:"Splunk Light is prone to a cross-site scriptin vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Splunk Light is affected by a cross-site scripting vulnerability
in the Splunk Web.");

  script_tag(name:"affected", value:"Splunk Light 6.4.x and 6.3.x");

  script_tag(name:"solution", value:"Update to version 6.4.1, 6.3.5 or later.");

  script_xref(name:"URL", value:"https://www.splunk.com/view/SP-CAAAPN9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^6\.4") {
  if (version_is_less(version: version, test_version: "6.4.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.4.1");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.3") {
  if (version_is_less(version: version, test_version: "6.3.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.3.5");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
