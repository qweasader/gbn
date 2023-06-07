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
  script_oid("1.3.6.1.4.1.25623.1.0.900302");
  script_version("2022-07-26T10:10:42+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:42 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2009-02-03 15:40:18 +0100 (Tue, 03 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2009-0320");
  script_name("Microsoft Windows taskmgr.exe Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://www.unifiedds.com/?p=44");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33440");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/500393/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");

  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker retrieve password related
  information and can cause brute force or benchmarking attacks.");
  script_tag(name:"affected", value:"- Microsoft Windows XP SP3 and prior

  - Microsoft Windows Server 2003 SP2 and prior");
  script_tag(name:"insight", value:"The I/O activity measurement of all processes allow to obtain sensitive
  information by reading the I/O other bytes column in taskmgr.exe to
  estimate the number of characters that a different user entered at a
  password prompt through 'runas.exe'.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Windows Operating System is prone to an information disclosure vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/en/us/default.aspx");
  exit(0);
}

include("secpod_reg.inc");

exit(0); ## plugin may results to FP

if(hotfix_check_sp(xp:4, win2003:3) > 0){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
