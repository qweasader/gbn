###############################################################################
# OpenVAS Vulnerability Test
#
# IBM WAS Administrative Console Information Disclosure Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810979");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-1137");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-22 16:47:45 +0530 (Mon, 22 May 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # we are not able to get the interim fix version...
  script_name("IBM WAS Administrative Console Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"IBM Websphere Application Server is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because IBM WebSphere
  Application Server has a potential for weaker than expected security with the
  Administrative Console due to some unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may
  allow a remote attacker to obtain sensitive information and gain unauthorized
  access to the admin console.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server versions
  8.5.0.0 through 8.5.5.11, 8.0.0.0 through 8.0.0.13");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) 8.5.5.12 or 8.0.0.14 or later or apply fix pack level available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21998469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98419");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!appVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if( (appVer =~ "^8\.5") && (version_is_less(version:appVer, test_version:'8.5.5.12'))){
  fix = "8.5.5.12";
}
else if( (appVer =~ "^8\.0") && (version_is_less(version:appVer, test_version:'8.0.0.14'))){
  fix = "8.0.0.14";
}

if(fix) {
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix);
  security_message(port:0, data:report);
  exit( 0 );
}

exit(99);
