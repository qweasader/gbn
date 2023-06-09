###############################################################################
# OpenVAS Vulnerability Test
#
# IBM WebSphere Application Server JSF Application Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.801998");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2011-1368");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-11-03 18:00:39 +0530 (Thu, 03 Nov 2011)");
  script_name("IBM WebSphere Application Server JSF Application Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/70168");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50463");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM45992");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24030916");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21474220");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will let remote unauthorized attackers to access
  or view files or obtain sensitive information.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server versions 8.x before 8.0.0.1.");

  script_tag(name:"insight", value:"The flaw is caused by improper handling of requests in 'JSF' applications.
  A remote attacker could gain unauthorized access to view files on the host.");

  script_tag(name:"solution", value:"Apply the latest Fix Pack (8.0.0.1 or later) or APAR PM45992.");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to an information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ibm:websphere_application_server";

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_equal(version:vers, test_version:"8.0.0.0")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.0.0.1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);