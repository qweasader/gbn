###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Application Server Multiple Unspecified Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802532");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2006-0284");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-12-07 13:11:01 +0530 (Wed, 07 Dec 2011)");
  script_name("Oracle Application Server Multiple Unspecified Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_oracle_app_server_detect.nasl");
  script_mandatory_keys("oracle/application_server/detected");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/545804");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16287");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1015499");

  script_tag(name:"impact", value:"An unspecified impact and attack vectors.");

  script_tag(name:"affected", value:"Oracle application server versions 9.0.4.2 and 10.1.2.0.2.");

  script_tag(name:"insight", value:"The flaws are due to unspecified errors in the oracle forms
  components.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"Oracle application server is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:oracle:application_server";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"9.0", test_version2:"9.0.4.2") ||
   version_in_range(version:vers, test_version:"10.1.2.0", test_version2:"10.1.2.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
