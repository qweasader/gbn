###############################################################################
# OpenVAS Vulnerability Test
#
# Ruby on Rails Acrive Record Security Bypass Vulnerability (Windows)
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

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809358");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2015-7577");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-08 15:43:00 +0000 (Thu, 08 Aug 2019)");
  script_tag(name:"creation_date", value:"2016-10-17 18:48:40 +0530 (Mon, 17 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Ruby on Rails Acrive Record Security Bypass Vulnerability (Windows)");

  script_tag(name:"summary", value:"Ruby on Rails is prone to security bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the script
  'activerecord/lib/active_record/nested_attributes.rb' does not properly implement
  a certain destroy option.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to bypass intended change restrictions by leveraging use of the nested
  attributes feature.");

  script_tag(name:"affected", value:"Ruby on Rails before 3.1.x and 3.2.x before 3.2.22.1,
  Ruby on Rails 4.0.x and 4.1.x before 4.1.14.1 and
  Ruby on Rails 4.2.x before 4.2.5.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Ruby on Rails 3.2.22.1 or 4.1.14.1 or
  4.2.5.1, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/01/25/10");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/81806");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("rails/detected", "Host/runs_windows");

  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

VULN = FALSE;

if( version_in_range( version: version, test_version: "3.1", test_version2: "3.2.22.0" ) )
{
  fix = "3.2.22.1";
  VULN = TRUE;
}

else if( version =~ "^(4\.)" )
{
  if( version_is_less( version: version, test_version: "4.1.14.1" ) )
  {
    fix = "4.1.14.1";
    VULN = TRUE;
  }
}

if( version =~ "^(4\.2)" )
{
  if( version_is_less( version: version, test_version: "4.2.5.1" ) )
  {
    fix = "4.2.5.1";
    VULN = TRUE;
  }
}

if( VULN )
{
  report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
