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
  script_oid("1.3.6.1.4.1.25623.1.0.900114");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-02 07:39:00 +0200 (Tue, 02 Sep 2008)");
  script_cve_id("CVE-2008-7107");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Privilege escalation");
  script_name("ESET Smart Security easdrv.sys Local Privilege Escalation Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"affected", value:"Eset Software Smart Security 3.0.667.0 and prior on Windows (All)");

  script_tag(name:"summary", value:"ESET Smart Security is prone to a local privilege escalation vulnerability.");

  script_tag(name:"insight", value:"The flaw exists due to an error in easdrv.sys driver file.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Eset Software Smart Security version 4.0.474 or later.");

  script_tag(name:"impact", value:"Local exploitation will allow attackers to execute arbitrary
  code with kernel level privileges to result in complete compromise of the system.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30719");

  exit(0);
}

 include("smb_nt.inc");

 if (!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 esetVer = registry_get_sz(key:"SOFTWARE\ESET\ESET Security\CurrentVersion\Info",
               item:"ProductVersion");
 if(!esetVer){
    exit(0);
 }

 if(egrep(pattern:"^([0-2]\..*|3\.0\.([0-5]?[0-9]?[0-9]|6[0-5][0-9]|66[0-7])\.0)$",
      string:esetVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
 }
