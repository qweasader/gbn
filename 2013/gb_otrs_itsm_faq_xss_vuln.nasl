# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:otrs:otrs_itsm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803941");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-2637");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-18 20:11:00 +0000 (Tue, 18 Feb 2020)");
  script_tag(name:"creation_date", value:"2013-09-27 15:11:15 +0530 (Fri, 27 Sep 2013)");
  script_name("OTRS ITSM XSS Vulnerability (OSA-2013-02)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS ITSM/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58930");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24922/");
  script_xref(name:"URL", value:"https://lists.otrs.org/hyperkitty/list/announce@lists.otrs.org/message/ZWUK3J7NXTB543S5IKS3GYE65HKR5RPF/");

  script_tag(name:"summary", value:"OTRS ITSM is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in application which fails to properly sanitize
  user-supplied input before using it");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the
  victim's cookie-based authentication credentials.");

  script_tag(name:"affected", value:"OTRS ITSM 3.2.0 through 3.2.2, 3.1.0 through 3.1.7 and 3.0.0
  through 3.0.6.");

  script_tag(name:"solution", value:"Update to OTRS ITSM version 3.2.3, 3.1.8 and 3.0.7 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.2") ||
   version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.7") ||
   version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.0.6")) {
  report = report_fixed_ver(installed_versions:vers, fixed_version:"3.2.3 / 3.1.8 / 3.0.7");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);