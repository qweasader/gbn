###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla SeaMonkey Multiple Vulnerabilities-02 November12 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803353");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-4209", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216",
                "CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4207", "CVE-2012-5842",
                "CVE-2012-5841", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833",
                "CVE-2012-5835", "CVE-2012-5839", "CVE-2012-5840");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-11-26 12:30:03 +0530 (Mon, 26 Nov 2012)");
  script_name("Mozilla SeaMonkey Multiple Vulnerabilities-02 November12 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51358");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56611");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56614");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56618");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56628");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56629");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56631");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56632");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56633");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56634");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56635");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56636");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56637");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56642");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027791");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027792");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-91.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-94.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-96.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-97.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-99.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-105.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-106.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the browser.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.14 on Windows");
  script_tag(name:"insight", value:"Multiple errors exist:

  - When combining SVG text with the setting of CSS properties.

  - Within the 'copyTexImage2D' implementation in the WebGL subsystem and
    in the XrayWrapper implementation.

  - Within 'str_unescape' in the Javascript engin and in 'XMLHttpRequest'
    objects created within sandboxes.");
  script_tag(name:"solution", value:"Upgrade to SeaMonkey version to 2.14 or later.");

  script_tag(name:"summary", value:"Mozilla Seamonkey is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

seaVer = get_kb_item("Seamonkey/Win/Ver");

if(seaVer)
{
  if(version_is_less(version:seaVer, test_version:"2.14"))
  {
    report = report_fixed_ver(installed_version:seaVer, fixed_version:"2.14");
    security_message(port:0, data:report);
    exit(0);
  }
}
