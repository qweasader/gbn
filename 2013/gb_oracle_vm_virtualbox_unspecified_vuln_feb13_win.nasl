# Copyright (C) 2013 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803300");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-0420");
  script_tag(name:"cvss_base", value:"2.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-02-01 11:01:15 +0530 (Fri, 01 Feb 2013)");
  script_name("Oracle VM VirtualBox Unspecified Vulnerability - Feb13 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");

  script_xref(name:"URL", value:"http://www.scip.ch/en/?vuldb.7413");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57383");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2013-1515902.html");

  script_tag(name:"impact", value:"Successful exploitation allows malicious local users to perform certain
  actions with escalated privileges.");

  script_tag(name:"affected", value:"Oracle VM VirtualBox versions 4.0, 4.1 and 4.2 on Windows");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error within the core component and can be
  exploited to cause a hang and manipulate certain VirtualBox accessible data.");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to an unspecified vulnerability.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:oracle:vm_virtualbox";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "4.0", test_version2: "4.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "Apply the patch", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
