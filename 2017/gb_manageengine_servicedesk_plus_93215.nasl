###############################################################################
# OpenVAS Vulnerability Test
#
# ManageEngine ServiceDesk Plus < 9.0 Access Bypass Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108158");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2016-4889");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-13 01:29:00 +0000 (Sat, 13 May 2017)");
  script_tag(name:"creation_date", value:"2017-05-12 09:37:58 +0200 (Fri, 12 May 2017)");
  script_name("ManageEngine ServiceDesk Plus < 9.0 Access Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_servicedesk_plus_consolidation.nasl");
  script_mandatory_keys("manageengine/servicedesk_plus/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93215");
  script_xref(name:"URL", value:"https://www.manageengine.com/products/service-desk/readme-9.0.html");

  script_tag(name:"summary", value:"ManageEngine ServiceDesk Plus is prone to an access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote authenticated guest user
  to have unspecified impact by leveraging failure to restrict access to unknown functions.");

  script_tag(name:"affected", value:"ManageEngine ServiceDesk Plus version prior to 9.0.");

  script_tag(name:"solution", value:"Upgrade to ManageEngine ServiceDesk Plus 9.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos['version'];
path = infos['location'];

if( version_is_less( version:version, test_version:"9.0b9000" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"9.0 (Build 9000)", install_path:path );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
