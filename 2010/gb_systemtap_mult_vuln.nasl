###############################################################################
# OpenVAS Vulnerability Test
#
# SystemTap Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800294");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2010-0411");
  script_name("SystemTap Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_systemtap_detect.nasl");

  script_mandatory_keys("SystemTap/Ver");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=559719");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38120");
  script_xref(name:"URL", value:"http://sourceware.org/git/gitweb.cgi?p=systemtap.git");

  script_tag(name:"impact", value:"Successful exploitation could allow local users to Denial of Service and
  potentially gain escalated privileges.");

  script_tag(name:"affected", value:"SystemTap versions 1.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to multiple integer signedness errors in the '__get_argv()'
  and '__get_compat_argv()' functions in 'tapset/aux_syscall.stp' via a process with a large number of arguments.");

  script_tag(name:"summary", value:"SystemTap is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Apply the available patch or update to version 1.2 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:systemtap:systemtap";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "1.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.2", install_path: location );
  report = report_fixed_ver(installed_version:version, vulnerable_range:"Less than or equal to 1.1");
  security_message(port: 0, data: report);
  exit( 0 );
}

exit( 99 );
