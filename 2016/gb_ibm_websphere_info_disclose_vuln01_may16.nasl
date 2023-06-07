###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Websphere Application Server Information Disclosure Vulnerability-01 May16
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
  script_oid("1.3.6.1.4.1.25623.1.0.808105");
  script_version("2021-10-15T11:13:32+0000");
  script_cve_id("CVE-2016-0306");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-15 11:13:32 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 19:52:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-05-20 17:02:37 +0530 (Fri, 20 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("IBM Websphere Application Server Information Disclosure Vulnerability-01 May16");

  script_tag(name:"summary", value:"IBM Websphere application server is prone to information-disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the
  improper TLS configuration when FIPS 140-2 is enabled.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to obtain sensitive information using man in the middle
  techniques.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  7.0 before 7.0.0.41, 8.0 before 8.0.0.13, and 8.5 before 8.5.5.10");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) version 7.0.0.41, or 8.0.0.13, or 8.5.5.10, or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21979231");

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

if(version_in_range(version:wasVer, test_version:"7.0", test_version2:"7.0.0.40"))
{
  fix = "7.0.0.41";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.0", test_version2:"8.0.0.12"))
{
  fix = "8.0.0.13";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.5", test_version2:"8.5.5.9"))
{
  fix = "8.5.5.10";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:wasVer, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
