# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:cisco:unified_communications_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107061");
  script_version("2022-03-10T09:57:15+0000");
  script_tag(name:"last_modification", value:"2022-03-10 09:57:15 +0000 (Thu, 10 Mar 2022)");
  script_tag(name:"creation_date", value:"2016-10-14 14:48:29 +0100 (Fri, 14 Oct 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)");

  script_cve_id("CVE-2016-6440");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Communications Manager iFrame Data Clickjacking Vulnerability (cisco-sa-20161012-ucm)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_cucm_consolidation.nasl");
  script_mandatory_keys("cisco/cucm/detected");

  script_tag(name:"summary", value:"The Cisco Unified Communications Manager (CUCM) may be
  vulnerable to data that can be displayed inside an iframe within a web page, which in turn could
  lead to a clickjacking attack. Protection mechanisms should be used to prevent this type of
  attack.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to a lack of proper input sanitization
  of iframe data within the HTTP requests sent to the device. An attacker could exploit this
  vulnerability by sending crafted HTTP packets with malicious iframe data.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to perform a clickjacking or
  phishing attack where the user is tricked into clicking on a malicious link. Protection
  mechanisms should be used to prevent this type of attack.");

  script_tag(name:"affected", value:"Cisco Unified Communications Manager 11.0(1.10000.10),
  11.5(1.10000.6) and 11.5(0.99838.4).");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161012-ucm");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

vers = str_replace( string:vers, find:"-", replace:"." );

if( (vers == "11.0.1.10000.10") || (vers == "11.5.1.10000.6") || (vers == "11.5.0.99838.4")) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See vendor advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
