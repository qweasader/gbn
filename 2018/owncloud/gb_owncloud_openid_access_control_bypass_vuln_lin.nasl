# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.813060");
  script_version("2021-09-29T07:24:12+0000");
  script_cve_id("CVE-2014-2048");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-29 07:24:12 +0000 (Wed, 29 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-13 15:05:00 +0000 (Wed, 13 Jun 2018)");
  script_tag(name:"creation_date", value:"2018-04-02 17:26:31 +0530 (Mon, 02 Apr 2018)");
  script_name("ownCloud 'OpenID' Access Control Bypass Vulnerability - Linux");

  script_tag(name:"summary", value:"ownCloud is prone to an access control bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insecure OpenID implementation used by
  user_openid in ownCloud 5.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to obtain access
  by leveraging an insecure OpenID implementation.");

  script_tag(name:"affected", value:"ownCloud versions prior to 5.0.15.");

  script_tag(name:"solution", value:"Update to ownCloud 5.0.15 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisories/insecure-openid-implementation");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/installed", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"5.0.15")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.0.15 or later", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);