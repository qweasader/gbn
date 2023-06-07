###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco WSA HTTPS Packet Processing Denial of Service Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807510");
  script_cve_id("CVE-2016-1288");
  script_version("2021-10-15T11:13:32+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-10-15 11:13:32 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-03-04 18:36:07 +0530 (Fri, 04 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cisco WSA HTTPS Packet Processing Denial of Service Vulnerability");

  script_tag(name:"summary", value:"Cisco WSA Software is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to incorrect processing of
  HTTPS packets");

  script_tag(name:"impact", value:"Successful exploitation allows an
  unauthenticated, remote attacker with the ability to negotiate a secure
  connection from within the trusted network to cause a denial of service (DoS)
  condition on the affected device.");

  script_tag(name:"affected", value:"Cisco ASA Software versions prior to
  8.5.3-051 and 9.0 before 9.0.0-485.");

  script_tag(name:"solution", value:"Upgrade to Cisco Web Security Appliance
  (WSA) software versions 8.5.3-051 or 9.0.0-485 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160302-wsa");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

version = str_replace( string:vers, find:"-", replace:"." );

if(version_is_less(version:version, test_version:'8.5.3.051'))
{
  fix = "8.5.3-051";
}

else if(version_in_range(version:version, test_version:"9.0", test_version2:"9.0.0.484"))
{
  fix = "9.0.0-485";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message( port:0, data:report );
  exit( 0 );
}
