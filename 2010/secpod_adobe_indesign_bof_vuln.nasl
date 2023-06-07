# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902085");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-06-25 16:56:31 +0200 (Fri, 25 Jun 2010)");
  script_cve_id("CVE-2010-2321");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe InDesign 'INDD' File Handling Remote Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40050");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59132");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1347");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_indesign_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to improper bounds checking when parsing 'INDD' files,
  which leads to buffer overflow.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Adobe InDesign CS5 or later.");
  script_tag(name:"summary", value:"Adobe InDesign is prone to a buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  by tricking a user into opening a specially crafted file.");
  script_tag(name:"affected", value:"Adobe InDesign CS3 10.0");
  exit(0);
}

include("version_func.inc");

adVer = get_kb_item("Adobe/InDesign/Ver");
if(isnull(adVer)){
  exit(0);
}

adobeVer = eregmatch(pattern:" ([0-9.]+)", string:adVer);
if(!isnull(adobeVer[1]) && ("CS3" >< adVer))
{
  if(version_is_equal(version:adobeVer[1], test_version:"10.0") ){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
