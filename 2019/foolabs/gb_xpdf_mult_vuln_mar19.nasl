# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113413");
  script_version("2023-10-27T16:11:32+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2019-06-20 10:52:47 +0000 (Thu, 20 Jun 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-01 20:17:00 +0000 (Sat, 01 Jan 2022)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-10018", "CVE-2019-10019", "CVE-2019-10020", "CVE-2019-10021", "CVE-2019-10022", "CVE-2019-10023",
                "CVE-2019-10024", "CVE-2019-10025", "CVE-2019-10026", "CVE-2019-12957", "CVE-2019-12958", "CVE-2019-14288",
                "CVE-2019-14289", "CVE-2019-14290", "CVE-2019-14291", "CVE-2019-14292", "CVE-2019-14293", "CVE-2019-14294");

  script_name("Xpdf <= 4.01.01 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_xpdf_detect.nasl");
  script_mandatory_keys("Xpdf/Linux/Ver");

  script_tag(name:"summary", value:"Xpdf is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - FPE in the function PostScriptFunction::exec at Function.cc for the psOpIdiv case

  - FPE in the function PSOutputDev::checkPageSlice at PSOutputDev.cc for nStripes

  - FPE in the function Splash::scaleImageYuXu at Splash.cc for x Bresenham parameters

  - FPE in the function ImageStream::ImageStream at Stream.cc for nComps

  - NULL pointer dereference in the function Gfx::opSetExtGState in Gfx.cc

  - FPE in the function PostScriptFunction::exec at Function.cc for the psOpMod case

  - FPE in the function Splash::scaleImageYuXu at Splash.cc for y Bresenham parameters

  - FPE in the function ImageStream::ImageStream at Stream.cc for nBits

  - FPE in the function PostScriptFunction::exec in Function.cc for the psOpRoll case

  - A buffer over-read could be triggered in FOFIType1C::convertToType1 in fofi/FoFiType1C.cc when
    the index number is larger than the charset array bounds. It can, for example, be triggered by
    sending a crafted PDF document to the pdftops tool. It allows an attacker to use a crafted PDF file
    to cause a Denial of Service or an information leak, or possibly have unspecified other impact.

  - A heap-based buffer over-read could be triggered in FoFiType1C::convertToType0 in fofi/FoFiType1C.cc when
    it is trying to access the second privateDicts array element, because the array has only one element allowed.

  - integer overflow in the function JBIG2Bitmap::combine at JBIG2Stream.cc for the 'one byte per line' case

  - integer overflow in the function JBIG2Bitmap::combine at JBIG2Stream.cc for the 'multiple bytes per line' case

  - out of bounds read in the function GfxPatchMeshShading::parse at GfxState.cc for typeA==6 case 2

  - out of bounds read in the function GfxPatchMeshShading::parse at GfxState.cc for typeA==6 case 3

  - out of bounds read in the function GfxPatchMeshShading::parse at GfxState.cc for typeA!=6 case 1

  - out of bounds read in the function GfxPatchMeshShading::parse at GfxState.cc for typeA!=6 case 2

  - use-after-free in the function JPXStream::fillReadBuf at JPXStream.cc due to an out of bounds read");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the application
  or access sensitive information.");

  script_tag(name:"affected", value:"Xpdf through version 4.01.01.");

  script_tag(name:"solution", value:"Update to version 4.02 or later.");

  script_xref(name:"URL", value:"https://forum.xpdfreader.com/viewtopic.php?f=3&t=41273");
  script_xref(name:"URL", value:"https://forum.xpdfreader.com/viewtopic.php?f=3&t=41274");
  script_xref(name:"URL", value:"https://forum.xpdfreader.com/viewtopic.php?f=3&t=41275");
  script_xref(name:"URL", value:"https://forum.xpdfreader.com/viewtopic.php?f=3&t=41276");
  script_xref(name:"URL", value:"https://forum.xpdfreader.com/viewtopic.php?f=3&t=41813");
  script_xref(name:"URL", value:"https://forum.xpdfreader.com/viewtopic.php?f=3&t=41815");

  exit(0);
}

CPE = "cpe:/a:foolabs:xpdf";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "4.01.01" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.02", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
