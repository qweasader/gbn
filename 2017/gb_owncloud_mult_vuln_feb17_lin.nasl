##############################################################################
# OpenVAS Vulnerability Test
#
# ownCloud Multiple Vulnerabilities Feb17 (Linux)
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

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106579");
  script_version("2021-09-09T13:03:05+0000");
  script_tag(name:"last_modification", value:"2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-02-08 16:01:56 +0700 (Wed, 08 Feb 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-08 01:50:00 +0000 (Wed, 08 Mar 2017)");

  script_cve_id("CVE-2017-5865", "CVE-2017-5866", "CVE-2017-5867");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud Multiple Vulnerabilities Feb17 (Linux)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ownCloud is prone to multiple vulnerabilities:

  - User enumeration with error messages

  - Information disclosure in email field dialog at sharing

  - Flooding logfiles with a 1 Bit BMP File");

  script_tag(name:"solution", value:"Update to ownCloud Server 8.1.11, 8.2.9, 9.0.7, 9.1.3 or later versions.");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2017-001");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2017-002");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2017-003");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "8.1.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.11");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^8\.2") {
  if (version_is_less(version: version, test_version: "8.2.9")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.2.9");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^9\.0") {
  if (version_is_less(version: version, test_version: "9.0.7")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.0.7");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^9\.1") {
  if (version_is_less(version: version, test_version: "9.1.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.1.3");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
