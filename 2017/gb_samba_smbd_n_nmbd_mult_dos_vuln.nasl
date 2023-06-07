###############################################################################
# OpenVAS Vulnerability Test
#
# Samba 'smbd and nmbd' Multiple Denial-of-Service Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811219");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2014-0244", "CVE-2014-3493");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-06-22 12:27:14 +0530 (Thu, 22 Jun 2017)");
  script_name("Samba 'smbd and nmbd' Multiple Denial-of-Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030455");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68148");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68150");
  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2014-3493");
  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2014-0244");

  script_tag(name:"summary", value:"Samba is prone to multiple denial-of-service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the nmbd NetBIOS name services daemon which causes the nmbd server
    to loop the CPU.

  - A memory corruption error. A valid unicode path names stored on disk can cause
    smbd to crash if an authenticated client attempts to read them using a
    non-unicode request.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow
  remote attackers to cause a denial-of-service condition.");

  script_tag(name:"affected", value:"Samba Server versions 3.6.x before 3.6.24,
  4.0.x before 4.0.19, and 4.1.x before 4.1.9.");

  script_tag(name:"solution", value:"Upgrade to Samba 3.6.24 or 4.0.19 or 4.1.9
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
loc = infos['location'];

if(vers =~ "^3\.6\."){
  if(version_is_less(version:vers, test_version:"3.6.24")){
    fix = "3.6.24";
  }
}

else if(vers =~ "^4\.[01]"){
  if(version_is_less(version:vers, test_version:"4.0.19")){
    fix = "4.0.19";
  }
  else if(version_in_range(version:vers, test_version:"4.1", test_version2:"4.1.8")){
    fix = "4.1.9";
  }
}

if(fix){
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:loc );
  security_message( data:report, port:port);
  exit(0);
}

exit(99);
