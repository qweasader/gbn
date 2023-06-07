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

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809291");
  script_version("2021-10-08T13:47:48+0000");
  script_cve_id("CVE-2015-5953");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-08 13:47:48 +0000 (Fri, 08 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-09-23 15:00:37 +0530 (Fri, 23 Sep 2016)");
  script_name("ownCloud Stored XSS Vulnerability (oC-SA-2015-010) - Linux");

  script_tag(name:"summary", value:"ownCloud is prone to a stored cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because the activity application does not
  sanitising all user provided input correctly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to
  inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"ownCloud Server before 7.0.5 and 8.0.x before 8.0.4.");

  script_tag(name:"solution", value:"Update to version 7.0.5, 8.0.4 later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-010");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/installed", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^[78]\.") {
  if(version_is_less(version:vers, test_version:"7.0.5")) {
    fix = "7.0.5";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"8.0.0", test_version2:"8.0.3")) {
    fix = "8.0.4";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:vers, fixed_version:fix);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);