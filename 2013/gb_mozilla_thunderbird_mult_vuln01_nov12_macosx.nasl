###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird Multiple Vulnerabilities-01 November12 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.803363");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2012-4209", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216",
                "CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4207", "CVE-2012-5842",
                "CVE-2012-5841", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833",
                "CVE-2012-5835", "CVE-2012-5839", "CVE-2012-5840");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-11-26 11:10:03 +0530 (Mon, 26 Nov 2012)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities-01 November12 (Mac OS X)");
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
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56641");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56642");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027791");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027792");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-91.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-92.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-93.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-100.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-101.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-103.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-105.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-106.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser.");
  script_tag(name:"affected", value:"Thunderbird version before 17.0 on Mac OS X");
  script_tag(name:"insight", value:"- The 'location' property can be accessed through 'top.location' with a
    frame whose name attributes value is set to 'top'.

  - Use-after-free error exists within the functions
    'nsTextEditorState::PrepareEditor', 'gfxFont::GetFontEntry',
    'nsWindow::OnExposeEvent' and 'nsPlaintextEditor::FireClipboardEvent'.

  - An error within the 'evalInSandbox()' when handling the 'location.href'
    property.

  - Error when rendering GIF images.");
  script_tag(name:"solution", value:"Upgrade to Thunderbird version to 17.0 or later.");
  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Thunderbird/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"17.0"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"17.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}
