# Copyright (C) 2017 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140123");
  script_version("2021-05-17T12:20:05+0000");
  script_tag(name:"last_modification", value:"2021-05-17 12:20:05 +0000 (Mon, 17 May 2021)");
  script_tag(name:"creation_date", value:"2017-01-19 11:44:37 +0100 (Thu, 19 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod", value:"98");

  script_name("Docker Compliance Check: Passed");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("Policy/gb_policy_docker.nasl");
  script_mandatory_keys("docker/docker_test/has_success_tests", "docker/docker_test/report_passed");

  script_tag(name:"summary", value:"Lists all the Docker Compliance Policy Checks which did pass.");

  exit(0);
}

include("misc_func.inc");
include("docker.inc");
# nb: Needs to be before docker_policy.inc to avoid an openvas-nasl-lint error
include("docker_policy_tests.inc");
include("docker_policy.inc");

if( ! f = get_kb_list( "docker/docker_test/success/*" ) )
  exit( 0 );

passed_count = max_index( keys( f ) );

if( passed_count == 0 )
  exit( 0 );

report = passed_count + ' Checks passed:\n\n';

foreach passed( sort( keys( f ) ) ) {

  _id = eregmatch( pattern:"docker/docker_test/success/([0-9.]+)", string:passed );
  if( isnull( _id[1] ) )
    continue;

  id = _id[1];
  reason = chomp( f[ passed ] );

  data = get_docker_test_data( id:id );

  report += " - " + data["title"] + '\n\nResult: ' + reason + '\n\n';
}

log_message( port:0, data:chomp( report ) );

exit( 0 );