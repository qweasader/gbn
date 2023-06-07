# Copyright (C) 2012 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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
  script_oid("1.3.6.1.4.1.25623.1.0.802444");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-0276", "CVE-2012-0277", "CVE-2012-0282");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-07-24 15:21:56 +0530 (Tue, 24 Jul 2012)");

  script_name("XnView Multiple Image Decompression Heap Overflow Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");

  script_tag(name:"summary", value:"XnView is prone to multiple heap based buffer overflow vulnerabilities");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Insufficient validation when decompressing SGI32LogLum compressed
    TIFF images.

  - Insufficient validation when decompressing SGI32LogLum compressed TIFF
    images where the PhotometricInterpretation encoding is set to LogL.

  - Insufficient validation when decompressing PCT images.

  - An indexing error when processing the ImageDescriptor structure of GIF
    images.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code on the
  system or cause a denial of service condition.");

  script_tag(name:"affected", value:"XnView versions prior to 1.99 on Windows");

  script_tag(name:"solution", value:"Update to XnView version 1.99 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19336/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54125");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19337/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19338/");
  script_xref(name:"URL", value:"http://newsgroup.xnview.com/viewtopic.php?f=35&t=25858");
  script_xref(name:"URL", value:"http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=48");
  script_xref(name:"URL", value:"http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=49");
  script_xref(name:"URL", value:"http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=50");

  exit(0);
}

include("version_func.inc");

if( !version = get_kb_item( "XnView/Win/Ver" ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"1.99" ) ) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.99");
  security_message(port:0, data:report);
  exit( 0 );
}

exit(99);
