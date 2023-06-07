###############################################################################
# OpenVAS Vulnerability Test
#
# CA Unified Infrastructure Management (UIM) Multiple Vulnerabilities
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

CPE = "cpe:/a:ca:unified_infrastructure_management";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106386");
  script_version("2021-10-14T10:01:27+0000");
  script_tag(name:"last_modification", value:"2021-10-14 10:01:27 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-11-11 11:33:27 +0700 (Fri, 11 Nov 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-21 01:59:00 +0000 (Tue, 21 Mar 2017)");

  script_cve_id("CVE-2016-5803", "CVE-2016-9164", "CVE-2016-9165");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CA Unified Infrastructure Management (UIM) Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ca_uim_detect.nasl");
  script_mandatory_keys("ca/unified_infrastructure_management/detected");

  script_tag(name:"summary", value:"CA UIM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"CA UIM is prone to multiple vulnerabilities:

  - Session ID Vulnerability (CVE-2016-9165)

  - diag.jsp Path Traversal Vulnerability (CVE-2016-9164)

  - download_lar.jsp Path Traversal Vulnerability (CVE-2016-5803)");

  script_tag(name:"impact", value:"An unauthenticated attacker may gain sensitive information.");

  script_tag(name:"affected", value:"CA UIM 8.47 and earlier.");

  script_tag(name:"solution", value:"Update to version 8.5.");

  script_xref(name:"URL", value:"https://techdocs.broadcom.com/us/product-content/recommended-reading/security-notices/ca20161109-01-security-notice-for-ca-unified-infrastructure-mgmt.html");

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

if (version_is_less(version: version, test_version: "8.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
