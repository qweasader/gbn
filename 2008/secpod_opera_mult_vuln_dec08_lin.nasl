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
  script_oid("1.3.6.1.4.1.25623.1.0.900082");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5679", "CVE-2008-5680", "CVE-2008-5681",
                "CVE-2008-5682", "CVE-2008-5683");
  script_name("Opera Web Browser Multiple Vulnerabilities - Dec08 (Linux)");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/920/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32864");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/921/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/923/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/924/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/linux/963/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");

  script_tag(name:"impact", value:"Successful remote attack could inject arbitrary code, information disclosure,
  execute java or plugin content and can even crash the application.");

  script_tag(name:"affected", value:"Opera version prior to 9.63 on Linux.");

  script_tag(name:"insight", value:"The flaws are due to

  - a buffer overflow error when handling certain text-area contents.

  - a memory corruption error when processing certain HTML constructs.

  - an input validation error in the feed preview feature when processing URLs.

  - an error in the built-in XSLT templates that incorrectly handle escaped
    content.

  - an error which could be exploited to reveal random data.

  - an error when processing SVG images embedded using img tags.");

  script_tag(name:"solution", value:"Upgrade to Opera 9.63.");

  script_tag(name:"summary", value:"Opera web browser is prone to multiple Vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"9.63")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"9.63");
  security_message(port: 0, data: report);
}
