# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900646");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1642", "CVE-2009-1641", "CVE-2009-1645");
  script_name("Mini-Stream Multiple Products Stack Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8629");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34864");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8630");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8633");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8632");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8631");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50374");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50375");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50376");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_mini_stream_prdts_detect.nasl");
  script_mandatory_keys("MiniStream/Products/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft malicious
'asx' or 'ram' files and execute arbitrary codes to cause stack overflow in
the context of the affected application.");
  script_tag(name:"affected", value:"Ripper version 3.0.1.1 (3.0.1.5) and prior
RM-MP3 Converter version 3.0.0.7 and prior
ASXtoMP3 Converter version 3.0.0.7 and prior");
  script_tag(name:"insight", value:"Inadequate boundary checks error of user supplied input to
Mini-stream products which causes stack overflow while processing .ram and
.asx files with overly long URIs.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Mini-Stream products is prone to a stack overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

rmMp3 = get_kb_item("MiniStream/RmToMp3/Conv/Ver");
if(rmMp3)
{
  if(version_is_less_equal(version:rmMp3, test_version:"3.0.0.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

asxMp3 = get_kb_item("MiniStream/AsxToMp3/Conv/Ver");
if(asxMp3)
{
  if(version_is_less_equal(version:asxMp3, test_version:"3.0.0.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

ripper = get_kb_item("MiniStream/Ripper/Ver");
if(ripper)
{
  #Ministream ripper 3.0.1.1 points to the version 3.0.1.5
  if(version_is_less_equal(version:ripper,test_version:"3.0.1.5"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
