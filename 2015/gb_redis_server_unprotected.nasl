# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:redis:redis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105291");
  script_version("2022-12-02T10:11:16+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-12-02 10:11:16 +0000 (Fri, 02 Dec 2022)");
  script_tag(name:"creation_date", value:"2015-06-05 15:48:46 +0200 (Fri, 05 Jun 2015)");
  script_name("Redis Server No Password");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/no_password");

  script_tag(name:"summary", value:"The remote Redis server is not protected with a password.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Evaluate if the remote Redis server is protected by a password.");

  script_tag(name:"insight", value:"It was possible to login without a password.");

  script_tag(name:"solution", value:"Set password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) ) # nb: To have a reference to the Detection-VT
  exit( 0 );

if( ! get_kb_item( "redis/" + port + "/no_password" ) )
  exit( 99 );

security_message( port:port );
exit( 0 );
