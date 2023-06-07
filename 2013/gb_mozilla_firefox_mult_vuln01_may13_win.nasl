###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Multiple Vulnerabilities -01 May13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803605");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-1681", "CVE-2013-1680", "CVE-2013-1679", "CVE-2013-1678",
                "CVE-2013-1677", "CVE-2013-1676", "CVE-2013-1675", "CVE-2013-1674",
                "CVE-2013-1673", "CVE-2013-1672", "CVE-2013-1671", "CVE-2013-1670",
                "CVE-2013-1669", "CVE-2013-0801");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2013-05-27 12:15:55 +0530 (Mon, 27 May 2013)");
  script_name("Mozilla Firefox Multiple Vulnerabilities -01 May13 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59855");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59859");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59860");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59861");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59862");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59863");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59864");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59865");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59868");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59869");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59870");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59872");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59873");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028555");
  script_xref(name:"URL", value:"http://www.dhses.ny.gov/ocs/advisories/2013/2013-051.cfm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  memory corruption, bypass certain security restrictions and compromise a user's system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 21.0 on Windows");

  script_tag(name:"insight", value:"- Unspecified vulnerabilities in the browser engine.

  - The Chrome Object Wrapper (COW) implementation does not prevent
    acquisition of chrome privileges.

  - Does not properly implement the INPUT element.

  - Does not properly maintain Mozilla Maintenance Service registry entries.

  - 'nsDOMSVGZoomEvent::mPreviousScale' and 'nsDOMSVGZoomEvent::mNewScale'
    functions do not initialize data structures.

  - Errors in 'SelectionIterator::GetNextSegment',
   'gfxSkipCharsIterator::SetOffsets' and '_cairo_xlib_surface_add_glyph'
   functions.

  - Use-after-free vulnerabilities in following functions,
    'nsContentUtils::RemoveScriptBlocker', 'nsFrameList::FirstChild', and
    'mozilla::plugins::child::_geturlnotify'.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 21.0 or later.");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");



  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");

if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"21.0"))
  {
    report = report_fixed_ver(installed_version:ffVer, fixed_version:"21.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}
