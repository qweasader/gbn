###############################################################################
# OpenVAS Vulnerability Test
#
# Opera Browser Multiple Vulnerabilities August-10 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801257");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_cve_id("CVE-2010-3021", "CVE-2010-3020", "CVE-2010-3019", "CVE-2010-2576");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Opera Browser Multiple Vulnerabilities August-10 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42407");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/966/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/967/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/968/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/windows/1061/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass certain security
  protections, execute arbitrary code, or cause denial-of-service conditions.");
  script_tag(name:"affected", value:"Opera Web Browser Version prior to 10.61");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the processing of painting operations on a canvas while
    certain transformations are being applied, which can be exploited to cause
    a heap-based buffer overflow.

  - An error when displaying the download dialog, which could allow attackers
    to trick a user into running downloaded executables.

  - An error when previewing a news feed, which can be exploited to execute
    script code and automatically subscribe the user to the feed.");
  script_tag(name:"solution", value:"Upgrade to Opera Web Browser Version 10.61 or later.");
  script_tag(name:"summary", value:"Opera Browser is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

ver = get_kb_item("Opera/Win/Version");

if(ver)
{
  if(version_in_range(version:ver, test_version:"10.0", test_version2:"10.60")){
    report = report_fixed_ver(installed_version:ver, vulnerable_range:"10.0 - 10.60");
    security_message(port: 0, data: report);
  }
}
