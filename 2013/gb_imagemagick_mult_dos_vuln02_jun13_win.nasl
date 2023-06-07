###############################################################################
# OpenVAS Vulnerability Test
#
# ImageMagick Multiple Denial of Service Vulnerabilities - 02 June13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803816");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2012-0248", "CVE-2012-0247");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-06-24 13:05:53 +0530 (Mon, 24 Jun 2013)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 18:39:00 +0000 (Fri, 31 Jul 2020)");
  script_name("ImageMagick Multiple Denial of Service Vulnerabilities - 02 June13 (Windows)");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027032");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51957");
  script_xref(name:"URL", value:"http://www.cert.fi/en/reports/2012_15/vulnerability595210.html");
  script_xref(name:"URL", value:"http://www.imagemagick.org/discourse-server/viewtopic.php?f=4&t=20286");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow a context-dependent attacker to cause
  denial of service result in loss of availability for the application.");
  script_tag(name:"affected", value:"ImageMagick version 6.7.5-7 and earlier on Windows.");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Error when parsing an IFD with IOP tag offsets pointing to the start
    of the IFD.

  - Improper sanitation of user supplied input when parsing offset and
    count values of the ResolutionUnit tag in EXIF IFD0.");
  script_tag(name:"solution", value:"Upgrade to ImageMagick version 6.7.5-8 or later.");
  script_tag(name:"summary", value:"ImageMagick is prone to multiple denial of service Vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"6.7.5.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.7.5.8", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
