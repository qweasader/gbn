###############################################################################
# OpenVAS Vulnerability Test
#
# HP Diagnostics Cross Site Scripting and Click Jacking Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
##########################################################################

CPE = "cpe:/a:hp:diagnostics_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812947");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2016-8521", "CVE-2016-8522");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-05 17:20:00 +0000 (Mon, 05 Mar 2018)");
  script_tag(name:"creation_date", value:"2018-02-23 13:48:49 +0530 (Fri, 23 Feb 2018)");
  script_name("HP Diagnostics Multiple Vulnerabilities (HPSBGN03689)");

  script_tag(name:"summary", value:"HP Diagnostics Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2016-8521: Click Jacking

  - CVE-2016-8522: Cross Site Scripting (XSS)");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site. This may
  let the attacker steal cookie-based authentication credentials and to gain unauthorized access to
  the affected application or obtain sensitive information.");

  script_tag(name:"affected", value:"HP Diagnostics Server versions 9.24 IP1, 9.26 and 9.26IP1.");

  script_tag(name:"solution", value:"Install the provided patches from vendor.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Patch available as solution and "IP" patch can't be detected.

  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-c05370100");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95427");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95427");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_diagnostics_server_detect.nasl");
  script_mandatory_keys("hp/diagnostics_server/detected");

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

if(version_is_equal(version:vers, test_version:"9.24") ||
   version_is_equal(version:vers, test_version:"9.26")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Apply Patch from vendor", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);