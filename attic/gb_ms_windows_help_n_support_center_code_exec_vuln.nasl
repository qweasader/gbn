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
  script_oid("1.3.6.1.4.1.25623.1.0.801358");
  script_version("2021-11-09T08:41:29+0000");
  script_tag(name:"last_modification", value:"2021-11-09 08:41:29 +0000 (Tue, 09 Nov 2021)");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_cve_id("CVE-2010-1885", "CVE-2010-2265");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Help and Support Center Remote Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59267");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1417");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2010/2219475");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-042");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code or compromise a vulnerable system.");

  script_tag(name:"affected", value:"- Microsoft Windows XP Service Pack 2/3

  - Microsoft Windows Server 2003 Service Pack 2");

  script_tag(name:"insight", value:"The flaws are due to:

  - An error in the 'MPC::HTML::UrlUnescapeW()' function within the Help and Support Center
  application (helpctr.exe) that does not properly check the return code of 'MPC::HexToNum()' when
  escaping URLs, which could allow attackers to bypass whitelist restrictions and invoke arbitrary
  help files.

  - An input validation error in the 'GetServerName()' function in the
  'C:\WINDOWS\PCHealth\HelpCtr\System\sysinfo\commonFunc.js' script invoked via 'ShowServerName()'
  in 'C:\WINDOWS\PCHealth\HelpCtr\System\sysinfo\sysinfomain.htm', which could be exploited by
  attackers to execute arbitrary scripting code.");

  script_tag(name:"summary", value:"Microsoft Windows is prone to a remote code execution (RCE)
  vulnerability.

  This VT has been replaced by 'Microsoft Help and Support Center Remote Code Execution
  Vulnerability (2229593)' (OID: 1.3.6.1.4.1.25623.1.0.902080)");

  script_tag(name:"solution", value:"The vendor has released a patch for the issue. Please see the
  references for more information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # This plugin is invalidated by secpod_ms10-042.nasl