###############################################################################
# OpenVAS Vulnerability Test
#
# Cscope Multiple Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:cscope:cscope";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800611");
  script_version("2020-04-27T09:00:11+0000");
  script_tag(name:"last_modification", value:"2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0148");
  script_name("Cscope < 15.7a Multiple Buffer Overflow Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_cscope_detect.nasl");
  script_mandatory_keys("cscope/detected");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1238");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490667");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=679527");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code or cause buffer overflows while parsing specially crafted files or directories.");

  script_tag(name:"affected", value:"Cscope version prior to 15.7a.");

  script_tag(name:"insight", value:"Boundary error exists in various functions using insecure sprintf, snprintf
  via long strings in input such as source-code tokens and pathnames.");

  script_tag(name:"solution", value:"Upgrade to Cscope version 15.7a.");

  script_tag(name:"summary", value:"This host has installed Cscope and is prone to multiple buffer
  overflow vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

location = infos["location"];
version = infos["version"];

if( version_is_less( version:version, test_version:"15.7a" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.7a", install_path:location );
  security_message(port: 0, data: report);
  exit( 0 );
}

exit( 99 );
