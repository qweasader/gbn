################################################################################
# OpenVAS Vulnerability Test
#
# Burp Suite CE Man in the Middle Security Bypass Vulnerability (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
################################################################################

CPE = "cpe:/a:portswigger:burp_suite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813612");
  script_version("2021-10-11T09:46:29+0000");
  script_cve_id("CVE-2018-1153");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-11 09:46:29 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-14 13:43:00 +0000 (Tue, 14 Aug 2018)");
  script_tag(name:"creation_date", value:"2018-06-19 16:08:53 +0530 (Tue, 19 Jun 2018)");
  script_name("Burp Suite CE 1.7.32 - 1.7.33 MITM Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"Burp Suite Community Edition is prone to a man-in-the-middle
  (MITM) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to Burp sends a couple of HTTPS requests without
  verifying the server certificate.");

  script_tag(name:"impact", value:"Successful exploitation will allow a man in the middle to
  intercept communication and inject new data.");

  script_tag(name:"affected", value:"Burp Suite Community Edition 1.7.32 and 1.7.33.");

  script_tag(name:"solution", value:"Update to version 1.7.34 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://releases.portswigger.net/2018/06/1734.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_burp_suite_ce_detect_macosx.nasl");
  script_mandatory_keys("BurpSuite/CE/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.7.32", test_version2:"1.7.33")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.7.34", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);