# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900112");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3732");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Denial of Service");
  script_name("VLC Media Player TTA Processing Integer Overflow Vulnerability");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_xref(name:"URL", value:"http://www.orange-bat.com/adv/2008/adv.08.16.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30718");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2394");
  script_tag(name:"summary", value:"VLC Media Player is prone to an integer overflow vulnerability.");
  script_tag(name:"insight", value:"The flaw is due to an overflow error when processing TTA data in Open()
        method in modules/demux/tta.c file.");
  script_tag(name:"affected", value:"VLC Media Player version 0.8.6i and prior on Windows (All).");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to VLC Media Player version 1.0 or later.");
  script_tag(name:"impact", value:"Remote exploitation will cause application to crash or allow
        execution of arbitrary code or deny the service.");
  exit(0);
}


 include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 vlcVer = registry_get_sz(key:"SOFTWARE\VideoLAN\VLC", item:"Version");
 if(egrep(pattern:"^0\.([0-7]\..*|8\.([0-5][a-z]?|6[a-i]?))$", string:vlcVer)){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
 }
