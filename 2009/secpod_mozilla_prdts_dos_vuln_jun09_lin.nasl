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
  script_oid("1.3.6.1.4.1.25623.1.0.900390");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2210");
  script_name("Mozilla Thunderbird/Seamonkey DoS Vulnerability June-09 (Linux)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51315");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35461");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-33.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_seamonkey_detect_lin.nasl", "gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code via
  e-mail messages, and result in Denial of Service condition.");

  script_tag(name:"affected", value:"Seamonkey version prior to 1.1.17 and
  Thunderbird version prior to 2.0.0.22 on Linux.");

  script_tag(name:"insight", value:"The flaw exists when application fails to handle user input messages via
  a multipart or alternative e-mail message containing a text or enhanced part
  that triggers access to an incorrect object type.");

  script_tag(name:"solution", value:"Upgrade to Seamonkey version 1.1.17

  Upgrade to Thunderbird version 2.0.0.22.");

  script_tag(name:"summary", value:"Thunderbird/Seamonkey is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

smVer = get_kb_item("Seamonkey/Linux/Ver");
if(smVer != NULL)
{
  if(version_is_less(version:smVer, test_version:"1.1.17")){
    report = report_fixed_ver(installed_version:smVer, fixed_version:"1.1.17");
    security_message(port: 0, data: report);
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Linux/Ver");
if(tbVer != NULL)
{
  if(version_is_less(version:tbVer, test_version:"2.0.0.22")){
    report = report_fixed_ver(installed_version:tbVer, fixed_version:"2.0.0.22");
    security_message(port: 0, data: report);
  }
}
