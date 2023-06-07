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
  script_oid("1.3.6.1.4.1.25623.1.0.902033");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-1098");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("Microsoft Windows '.ani' file Denial of Service vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56756");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38579");
  script_xref(name:"URL", value:"http://code.google.com/p/skylined/issues/detail?id=3");
  script_xref(name:"URL", value:"http://skypher.com/index.php/2010/03/08/ani-file-bitmapinfoheader-biclrused-bounds-check-missing/");

  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");

  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploits will cause application to crash or become
unresponsive, denying service to legitimate users.");
  script_tag(name:"affected", value:"- Microsoft Windows 2000 SP4 and earlier

  - Microsoft Windows XP SP3 and earlier

  - Microsoft Windows 2003 SP2 and earlier");
  script_tag(name:"insight", value:"The flaw is due to improper bounds checking when processing
'.ani' files which can be exploited via crafted '.ani' file to cause the system
to consume an overly large amount of memory and become unresponsive.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host has ANI parser in Microsoft Windows and is prone to
denial of dervice vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) == 0){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
