# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144861");
  script_version("2023-03-09T10:20:45+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:45 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"creation_date", value:"2020-10-29 04:54:00 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-25 20:38:00 +0000 (Thu, 25 Feb 2021)");

  script_cve_id("CVE-2020-10254");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud < 10.4 Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");

  script_tag(name:"summary", value:"ownCloud is prone to an access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It was possible to access the preview-image of a password-protected
  public-link. The severity of the issue is reduced to low because the attacker needs to know the public-link
  hash and the original filename of the image.");

  script_tag(name:"impact", value:"An attacker can bypass authentication on a password-protected image by displaying its preview.");

  script_tag(name:"affected", value:"ownCloud prior to version 10.4.");

  script_tag(name:"solution", value:"Update to version 10.4 or later.");

  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/public-link-password-bypass-via-image-previews/");

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

if (version_is_less(version: version, test_version: "10.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
