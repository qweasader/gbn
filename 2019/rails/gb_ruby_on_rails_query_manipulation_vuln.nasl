# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.114115");
  script_version("2021-10-07T07:48:17+0000");
  script_tag(name:"last_modification", value:"2021-10-07 07:48:17 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"creation_date", value:"2019-07-25 13:34:28 +0200 (Thu, 25 Jul 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2013-3221");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Ruby on Rails Query Manipulation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl");
  script_mandatory_keys("rails/detected");

  script_tag(name:"summary", value:"Ruby on Rails is prone to a query manipulation vulnerability.");

  script_tag(name:"insight", value:"The 'Active Record' component in Ruby on Rails
  does not ensure that the declared data type of a database column is used during
  comparisons of input values to stored values in that column.");

  script_tag(name:"impact", value:"Successful exploitation will make it easier for
  remote attackers to conduct data-type injection attacks against Ruby on Rails
  applications via a crafted value.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Ruby on Rails versions 2.3.x, 3.0.x, 3.1.x and 3.2.x.");

  script_tag(name:"solution", value:"We recommend to update to Ruby on Rails 4.0.0 or later. However, refer to the linked
  forum post for additional insight. Later versions definitely made fundamental changes to this component, which might
  mitigate this vulnerability to some degree. According to the forum post, the risk will remain, as long as this feature
  is still supported.");

  script_xref(name:"URL", value:"https://groups.google.com/forum/#!original/rubyonrails-security/ZOdH5GH5jCU/zsFgirjAOx8J");
  script_xref(name:"URL", value:"https://www.rapid7.com/db/vulnerabilities/ruby_on_rails-cve-2013-3221");

  exit(0);
}

CPE = "cpe:/a:rubyonrails:rails";

include( "version_func.inc" );
include( "host_details.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "2.3.0", test_version2: "3.2.22.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
