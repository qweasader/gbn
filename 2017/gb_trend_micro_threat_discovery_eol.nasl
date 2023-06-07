###############################################################################
# OpenVAS Vulnerability Test
#
# Trend Micro Threat Discovery Appliance End of Life (EOL) Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140248");
  script_version("2020-12-09T13:05:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-12-09 13:05:49 +0000 (Wed, 09 Dec 2020)");
  script_tag(name:"creation_date", value:"2017-04-12 09:30:26 +0200 (Wed, 12 Apr 2017)");
  script_name("Trend Micro Threat Discovery Appliance End of Life (EOL) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_trend_micro_threat_discovery_detect.nasl");
  script_mandatory_keys("trendmicro/threat_discovery/detected");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1105727-list-of-end-of-life-eol-end-of-support-eos-trend-micro-products");

  script_tag(name:"summary", value:"The remote Trend Micro Threat Discovery Appliance has reached EOL
  at 30-Jun-16. There are known security issues with this appliances which are not longer patched.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or replace
  the product by another one.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

CPE = "cpe:/a:trendmicro:threat_discovery";

include( "host_details.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! location = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

report = "The target is a Trend Micro Threat Discovery Appliance which has reached EOL at 30-Jun-16.";
security_message( data: report, port: port );

exit( 0 );
