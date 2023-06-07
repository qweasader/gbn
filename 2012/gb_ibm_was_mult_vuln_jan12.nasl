###############################################################################
# OpenVAS Vulnerability Test
#
# IBM WebSphere Application Server (WAS) Multiple Vulnerabilities - (Jan2012)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802412");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2011-5066", "CVE-2011-5065", "CVE-2011-1377");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-01-18 17:27:41 +0530 (Wed, 18 Jan 2012)");
  script_name("IBM WebSphere Application Server (WAS) Multiple Vulnerabilities - (Jan2012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50310");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51559");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51560");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72299");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27011716");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM50205");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM43792");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg24031034");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to conduct cross-site scripting
  attacks or to obtain sensitive information and cause a denial of service.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS) version 6.1 before 6.1.0.41.");

  script_tag(name:"insight", value:"The flaws are due to

  - An unspecified error exists in a WS-Security policy enabled Java API for
  XML Web Services (JAX-WS) application.

  - A Certain unspecified input passed to the web messaging component is not
  properly sanitised before being returned to the user.

  - A SibRaRecoverableSiXaResource class in the Default Messaging Component,
  does not properly handle a Service Integration Bus (SIB) dump operation
  involving the First Failure Data Capture (FFDC) introspection code.");

  script_tag(name:"solution", value:"Upgrade to version 6.1.0.41 or later.");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ibm:websphere_application_server";

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"6.1", test_version2:"6.1.0.40")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.1.0.41");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);