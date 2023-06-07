###############################################################################
# OpenVAS Vulnerability Test
#
# IBM BigFix (Formerly Tivoli Endpoint Manager) Multiple Vulnerabilities Oct16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Updated By Rajat Mishra <rajatm@secpod.com> On 2018-04-03 for CVE-2016-0295
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:ibm:tivoli_endpoint_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809368");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-0292", "CVE-2016-0397", "CVE-2016-0295");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-16 17:52:00 +0000 (Fri, 16 Mar 2018)");
  script_tag(name:"creation_date", value:"2016-10-18 13:23:56 +0530 (Tue, 18 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM BigFix (Formerly Tivoli Endpoint Manager) Multiple Vulnerabilities Oct16");

  script_tag(name:"summary", value:"IBM BigFix (Formerly Tivoli Endpoint Manager) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - Cleartext system password is used.

  - Improper validation of incoming http traffic.

  - Improper validation of user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information and let local users discover the
  cleartext system password by reading a report and hijack the authentication of
  arbitrary users, perform cross-site scripting attacks, web cache poisoning,
  and other malicious activities.");

  script_tag(name:"affected", value:"IBM BigFix (Formerly Tivoli Endpoint
  Manager) versions 9.x before 9.5.2.");

  script_tag(name:"solution", value:"Upgrade to IBM BigFix (Formerly Tivoli
  Endpoint Manager) version 9.5.2, or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21985907");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92467");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92468");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92464");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21985830");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_endpoint_manager_web_detect.nasl");
  script_mandatory_keys("ibm_endpoint_manager/installed");
  script_require_ports("Services/www", 52311);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!tivPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!tivVer = get_app_version(cpe:CPE, port:tivPort)){
  exit(0);
}

if(version_in_range(version:tivVer, test_version:"9.0", test_version2:"9.5.1"))
{
  report = report_fixed_ver(installed_version:tivVer, fixed_version:"9.5.2");
  security_message(port:tivPort, data:report);
  exit(0);
}
exit(0);
