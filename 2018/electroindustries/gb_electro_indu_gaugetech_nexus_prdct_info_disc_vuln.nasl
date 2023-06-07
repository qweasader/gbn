###############################################################################
# OpenVAS Vulnerability Test
#
# Electro Industries GaugeTech Nexus series Products Information Disclosure Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/h:electroindustries_gaugetech:total_websolutions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813629");
  script_version("2021-10-11T09:46:29+0000");
  script_cve_id("CVE-2018-12921");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-11 09:46:29 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-31 11:56:00 +0000 (Fri, 31 Aug 2018)");
  script_tag(name:"creation_date", value:"2018-07-04 11:28:37 +0530 (Wed, 04 Jul 2018)");

  script_name("Electro Industries GaugeTech Nexus series Products Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"Electro Industries GaugeTech Nexus series Product is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check if response is disclosing sensitive information or not.");

  script_tag(name:"insight", value:"The flaw is due to improper input validation
  by the 'meter_information.htm', 'diag_system.htm' and 'diag_dnp_lan_wan.htm' URI's.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Electro Industries GaugeTech Nexus series
  Products.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"https://www.seebug.org/vuldb/ssvid-97371");
  script_xref(name:"URL", value:"https://electroind.com/downloads/nexus-meters");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_electro_industries_gaugetech_total_web_solutions_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ElectroIndustries/GaugeTech/TotalWebSolutions/installed");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! elePort = get_app_port( cpe:CPE ) ) exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:elePort ) ) exit( 0 );
if( dir == "/" ) dir = "";

url = dir + "/diag_dnp_lan_wan.htm";

if( http_vuln_check(port:elePort, url:url, check_header:TRUE,
                    pattern:'<title>DNP LAN/WAN Status</title>','Electro Industries/GaugeTech',
                    extra_check:make_list('DNP TCP Connection', 'Mode:'))) {
  report = http_report_vuln_url(port:elePort, url:url);
  security_message( port:elePort, data:report );
  exit(0);
}

exit(99);
