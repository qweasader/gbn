# Copyright (C) 2011 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902457");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_cve_id("CVE-2011-1355", "CVE-2011-1356");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("IBM WebSphere Application Multiple Vulnerabilities Jul-11");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68570");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48709");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48710");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68571");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM42436");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote users to gain sensitive information
  to redirect users to arbitrary web sites and conduct phishing attacks via the logoutExitPage parameter.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server 6.1 before 6.1.0.39 and 7.0 before 7.0.0.19.");

  script_tag(name:"insight", value:"Multiple flaws are due to an error in,

  - handling 'logoutExitPage' parameter, which allows to bypass security restrictions.

  - handling Administration Console requests, which allows local attacker to obtain sensitive information.");

  script_tag(name:"solution", value:"Upgrade to BM WebSphere Application Server 6.1.0.39 or 7.0.0.19.");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ibm:websphere_application_server";

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"6.1", test_version2:"6.1.0.38") ||
   version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.0.18")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.1.0.39/7.0.0.19");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
