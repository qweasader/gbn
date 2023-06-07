###############################################################################
# OpenVAS Vulnerability Test
#
# Samba Server 'SMB3' MitM Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811906");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-12151");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-09-22 13:19:22 +0530 (Fri, 22 Sep 2017)");
  script_name("Samba Server 'SMB3' MitM Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl", "gb_smb_version_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2017-12151.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100917");

  script_tag(name:"summary", value:"Samba is prone to a MitM vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A connection actually made use of the
  SMB3 encryption, any redirected connection would lose the requirement
  for encryption and also the requirement for signing.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read and/or alter the content of the connection.");

  script_tag(name:"affected", value:"Samba versions 4.1.0 to 4.6.7");

  script_tag(name:"solution", value:"Upgrade to Samba 4.6.8, 4.5.14 or 4.4.16");

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

if(!get_kb_item("smb_v3/supported")) exit(0);

#Since patch is given as 4.5.14 4.4.16 also.
if(vers == "4.5.14" || vers == "4.4.16"){
 exit(0);
}
else if(version_in_range(version:vers, test_version:"4.1", test_version2:"4.6.7")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.4.16, or 4.5.14, or 4.6.8", install_path:loc);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
