###############################################################################
# OpenVAS Vulnerability Test
#
# Unchecked Buffer in PPTP Implementation Could Enable DOS Attacks (Q329834)
#
# Authors:
# Michael Scheidell SECNAP Network Security
#
# Copyright:
# Copyright (C) 2002 SECNAP Network Security, LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11178");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-1214");
  script_name("Unchecked Buffer in PPTP Implementation Could Enable DOS Attacks (Q329834)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 SECNAP Network Security, LLC");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"Hotfix to fix Unchecked Buffer in PPTP Implementation
  (Q329834) is not installed.");

  script_tag(name:"insight", value:"A security vulnerability results in the Windows 2000 and
  Windows XP implementations because of an unchecked buffer in a section of code that processes
  the control data used to establish, maintain and tear down PPTP connections. By delivering
  specially malformed PPTP control data to an affected server, an attacker could corrupt kernel
  memory and cause the system to fail, disrupting any work in progress on the system.");

  script_tag(name:"impact", value:"Denial of service");

  script_tag(name:"affected", value:"- Microsoft Windows 2000

  - Microsoft Windows XP");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-063");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5807");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6067");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q329834") > 0 )
  security_message(port:0);
