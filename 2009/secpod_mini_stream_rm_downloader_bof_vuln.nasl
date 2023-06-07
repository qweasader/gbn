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
  script_oid("1.3.6.1.4.1.25623.1.0.902036");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-05-22 08:49:17 +0200 (Fri, 22 May 2009)");
  script_cve_id("CVE-2009-4761");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mini Stream RM Downloader '.smi' File Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8594");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34794");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50266");

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_dependencies("secpod_mini_stream_prdts_detect.nasl");
  script_mandatory_keys("MiniStream/RMDown/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attacker to execute
arbitrary code on the system or cause the application to crash.");
  script_tag(name:"affected", value:"Mini-stream RM Downloader version 3.0.0.9 and prior.");
  script_tag(name:"insight", value:"The flaw is caused by improper bounds checking when processing
'.smi' files and can be exploited via crafted '.smi' file to cause buffer
overflow.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Mini-stream RM Downloader is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

rmDownVer = get_kb_item("MiniStream/RMDown/Ver");
if(!rmDownVer){
  exit(0);
}

# Mini-stream RM Downloader version 3.0.0.9 => 3.0.2.1
if(version_is_less_equal(version:rmDownVer, test_version:"3.0.2.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
