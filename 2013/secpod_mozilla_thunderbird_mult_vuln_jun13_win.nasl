# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.903216");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687",
                "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694",
                "CVE-2013-1697", "CVE-2013-1682");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2013-06-26 16:56:12 +0530 (Wed, 26 Jun 2013)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities - June 13 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53970");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60766");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60773");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60774");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60776");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60777");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60778");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60783");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60784");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60787");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028702");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-50.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  obtain potentially sensitive information, gain escalated privileges, bypass
  security restrictions, and perform unauthorized actions. Other attacks may
  also be possible.");
  script_tag(name:"affected", value:"Thunderbird versions before 17.0.7 on Windows");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - PreserveWrapper does not handle lack of wrapper.

  - Error in processing of SVG format images with filters to read pixel values.

  - Does not prevent inclusion of body data in XMLHttpRequest HEAD request.

  - Multiple unspecified vulnerabilities in the browser engine.

  - Does not properly handle onreadystatechange events in conjunction with
    page reloading.

  - System Only Wrapper (SOW) and Chrome Object Wrapper (COW), does not
    restrict XBL user-defined functions.

  - Use-after-free vulnerability in 'nsIDocument::GetRootElement' and
    'mozilla::dom::HTMLMediaElement::LookupMediaElementURITable' functions.

  - XrayWrapper does not properly restrict use of DefaultValue for method calls.");
  script_tag(name:"solution", value:"Upgrade to Thunderbird version to 17.0.7 or later.");
  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"17.0.7")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"17.0.7");
    security_message(port: 0, data: report);
    exit(0);
  }
}
