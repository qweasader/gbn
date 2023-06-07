###############################################################################
# OpenVAS Vulnerability Test
#
# Symantec Messaging Gateway Decomposer Engine Security Update (SYM16-015)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

CPE = "cpe:/a:symantec:messaging_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105897");
  script_version("2021-10-12T10:01:28+0000");
  script_cve_id("CVE-2016-5310", "CVE-2016-5309");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-10-12 10:01:28 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 17:50:00 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"creation_date", value:"2016-09-21 10:37:51 +0200 (Wed, 21 Sep 2016)");

  script_name("Symantec Messaging Gateway Decomposer Engine Security Update (SYM16-015)");

  script_tag(name:"summary", value:"Symantec has released an update to address two issues in the RAR file parser
component of the antivirus decomposer engine used by multiple Symantec products.");

  script_tag(name:"impact", value:"Parsing of maliciously formatted RAR container files may cause an application-level denial of service condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to SMG 10.6.2 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160919_00");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_messaging_gateway_detect.nasl");
  script_mandatory_keys("symantec_smg/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version(cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version =~ "^10\." )
{
  if( version_is_less( version:version, test_version:"10.6.2" ) )
  {
    report = report_fixed_ver( installed_version:version, fixed_version:'10.6.2' );
    security_message( port:0, data:report );
    exit(0);
  }
}

exit( 99 );
