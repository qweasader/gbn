# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902777");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2011-3666");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-12-22 13:17:34 +0530 (Thu, 22 Dec 2011)");
  script_name("Mozilla Products jar Files Remote Code Execution Vulnerability (MAC OS X)");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51139");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-59.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code in
  the context of the user running an affected application.");
  script_tag(name:"affected", value:"Thunderbird version prior to 3.1.17
  Mozilla Firefox version prior to 3.6.25");
  script_tag(name:"insight", value:"The flaw is due to not considering '.jar' files to be executable files
  which allows remote attackers to bypass intended access restrictions via a
  crafted file.");
  script_tag(name:"summary", value:"Mozilla firefox/thunderbird is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.25 or later, Upgrade to Thunderbird version to 3.1.17 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.6.25"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"3.6.25");
    security_message(port: 0, data: report);
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.1.17")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"3.1.17");
    security_message(port: 0, data: report);
  }
}
