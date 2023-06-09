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
  script_oid("1.3.6.1.4.1.25623.1.0.902055");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-2004", "CVE-2010-2009");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("BS.Player '.bsl' File Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38221");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37831");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38568");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55708");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0148");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_bsplayer_detect.nasl");
  script_mandatory_keys("BSPlayer/Ver");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A boundary error while processing specially crafted 'BSI' files, when user
opens a specially crafted 'BSI' file containing an overly long 'Skin' key
in the 'Options' section.

  - A boundary error in the processing of 'ID3' tags when a user adds a specially
crafted mp3 file to the media library.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"BS Player is prone to multiple buffer overflow vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
arbitrary code by tricking a user into opening a specially files. Failed
attacks will cause denial-of-service conditions.");
  script_tag(name:"affected", value:"BS.Global BS.Player version 2.51 Build 1022 and prior.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

bsver = get_kb_item("BSPlayer/Ver");
if(!bsver){
exit(0);
}

if(bsver != NULL)
{
  if(version_is_less_equal(version:bsver, test_version:"2.51.1022")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
