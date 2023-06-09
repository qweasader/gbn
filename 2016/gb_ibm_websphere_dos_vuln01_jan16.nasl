###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Websphere Application Server Denial Of Service Vulnerability 01 Jan16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806827");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2014-0964");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2016-01-19 13:15:39 +0530 (Tue, 19 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("IBM Websphere Application Server Denial Of Service Vulnerability 01 Jan16");

  script_tag(name:"summary", value:"IBM Websphere application server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to when running the
  Heartbleed scanning tools or if sending specially-crafted Heartbeat
  messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service via crafted TLS traffic.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  6.1.0.0 through 6.1.0.47 and 6.0.2.0 through 6.0.2.43");

  script_tag(name:"solution", value:"Apply Interim Fix PI16981 from the vendor");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.scaprepo.com/view.jsp?id=CVE-2014-0964");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67322");
  script_xref(name:"URL", value:"http://www-304.ibm.com/support/docview.wss?uid=swg21673808");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21671835");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:wasVer, test_version:"6.1", test_version2:"6.1.0.47"))
{
  fix = "Apply Interim Fix PI16981";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"6.0.2.0", test_version2:"6.0.2.43"))
{
  fix = "Apply Interim Fix PI17128";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:wasVer, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);