###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Websphere Application Server Multiple Vulnerabilities -07 Jan16
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
  script_oid("1.3.6.1.4.1.25623.1.0.806833");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2012-0716", "CVE-2012-2170", "CVE-2012-0720", "CVE-2012-0717");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2016-01-19 16:52:40 +0530 (Tue, 19 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Websphere Application Server Multiple Vulnerabilities -07 Jan16");

  script_tag(name:"summary", value:"IBM Websphere application server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - The Application Snoop Servlet does not properly restrict access.

  - insufficient validation of requests by Administration Console.

  - A security bypass vulnerability when a certain SSLv2 configuration with
    client authentication is used.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attacker to bypass authentication, to inject arbitrary web script
  or HTML and to obtain sensitive information.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  version 7.0 before 7.0.0.23");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) version 7.0.0.23 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21595172");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52721");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52724");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:wasVer, test_version:"7.0", test_version2:"7.0.0.22"))
{
  report = report_fixed_ver(installed_version:wasVer, fixed_version:"7.0.0.23");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);