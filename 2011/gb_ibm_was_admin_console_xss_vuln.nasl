###############################################################################
# OpenVAS Vulnerability Test
#
# IBM WebSphere Application Server Admin Console Cross-site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801999");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2009-2748");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-11-04 14:37:49 +0530 (Fri, 04 Nov 2011)");
  script_name("IBM WebSphere Application Server Admin Console Cross-site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54229");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37015");
  script_xref(name:"URL", value:"http://www.ibm.com/support/docview.wss?uid=swg1PK99481");
  script_xref(name:"URL", value:"http://www.ibm.com/support/docview.wss?uid=swg1PK92057");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to inject malicious script
  into a Web page. Further an attacker could use this vulnerability to steal
  the victim's cookie-based authentication credentials.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS) version 7.1 before 7.0.0.7
  IBM WebSphere Application Server (WAS) version 6.1 before 6.1.0.29.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input in the
  Administration Console, which allows the remote attacker to inject malicious script into a Web page.");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution", value:"For WebSphere Application Server 6.1:

  Apply the latest Fix Pack (6.1.0.29 or later) or APAR PK92057

  For WebSphere Application Server 7.1:

  Apply the latest Fix Pack (7.0.0.7 or later) or APAR PK92057.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ibm:websphere_application_server";

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.0.6") ||
   version_in_range(version:vers, test_version:"6.1", test_version2:"6.1.0.28")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.0.0.7/6.1.0.29");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);