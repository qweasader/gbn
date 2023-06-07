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
  script_oid("1.3.6.1.4.1.25623.1.0.900050");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-10-15 19:56:48 +0200 (Wed, 15 Oct 2008)");
  script_cve_id("CVE-2008-4023");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Active Directory Could Allow Remote Code Execution Vulnerability (957280)");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-060");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31609");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could result in buffer overflow via a
  specially crafted request.");

  script_tag(name:"affected", value:"Microsoft Windows 2000 Server Service Pack 4 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an incorrect memory allocation when processing LDAP
  and LDAPS requests.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-060.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5) <= 0){
  exit(0);
}

# Active Directory
if(!registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\NTDS\Performance")){
  exit(0);
}

if(hotfix_missing(name:"957280") == 0){
  exit(0);
}

ntdsPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                           item:"Install Path");
if(!ntdsPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ntdsPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:ntdsPath + "\ntdsa.dll");

ntdsVer = GetVer(file:file, share:share);
if(!ntdsVer){
  exit(0);
}

if(ereg(pattern:"^5\.0\.2195\.([0-6]?[0-9]?[0-9]?[0-9]|70[0-9][0-9]|" +
                "71([0-6][0-9]|7[0-7]))$", string:ntdsVer)){
   security_message(port:0);
}
