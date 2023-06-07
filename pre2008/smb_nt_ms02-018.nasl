###############################################################################
# OpenVAS Vulnerability Test
#
# Cumulative Patch for Internet Information Services (Q327696)
#
# Authors:
# Michael Scheidell <scheidell at secnap.net>
# Updated: 2009/04/23
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2002 Michael Scheidell
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
  script_oid("1.3.6.1.4.1.25623.1.0.10943");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-0147", "CVE-2002-0149",
                "CVE-2002-0150", "CVE-2002-0224",
                "CVE-2002-0869", "CVE-2002-1182",
                "CVE-2002-1180", "CVE-2002-1181");
  script_xref(name:"IAVA", value:"2002-A-0002");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Cumulative Patch for Internet Information Services (Q327696)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michael Scheidell");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"Check if the Cumulative Patch for Microsoft IIS (Q327696) is installed.");

  script_tag(name:"impact", value:"Ten new vulnerabilities, the most serious of which could enable code of an attacker's choice
  to be run on a server.");

  script_tag(name:"affected", value:"- Microsoft Internet Information Services 4.0

  - Microsoft Internet Information Services 5.0

  - Microsoft Internet Information Services 5.1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-062");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4006");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4474");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4476");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4478");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4490");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6069");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6070");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6071");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6072");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_iis_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7, win2k:3, xp:1 ) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q811114") > 0 &&
     hotfix_missing(name:"Q327696") > 0  )
  security_message(port:0);
