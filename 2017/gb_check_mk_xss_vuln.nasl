##############################################################################
# OpenVAS Vulnerability Test
#
# Check_MK XSS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140596");
  script_version("2021-09-15T10:01:53+0000");
  script_tag(name:"last_modification", value:"2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-12-12 11:05:49 +0700 (Tue, 12 Dec 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-26 18:10:00 +0000 (Tue, 26 Dec 2017)");

  script_cve_id("CVE-2017-11507");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Check_MK XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Check_MK is prone to a cross-site scripting vulnerability.");

  script_tag(name:"insight", value:"A cross site scripting (XSS) vulnerability exists in Check_MK, allowing an
unauthenticated attacker to inject arbitrary HTML or JavaScript via the output_format parameter, and the username
parameter of failed HTTP basic authentication attempts, which is returned unencoded in an internal server error
page.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Check_MK before version 1.2.8x and 1.4.0x.");

  script_tag(name:"solution", value:"Update to version 1.2.8p25, 1.4.0p9 or later.");

  script_xref(name:"URL", value:"http://mathias-kettner.com/check_mk_werks.php?werk_id=7661");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.2.8p25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.8p25");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.4.0", test_version2: "1.4.0p8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.0p9");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
