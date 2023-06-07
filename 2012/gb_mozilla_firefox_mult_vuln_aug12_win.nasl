###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Multiple Vulnerabilities - August12 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803017");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-3965", "CVE-2012-3973");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-08-30 14:55:59 +0530 (Thu, 30 Aug 2012)");
  script_name("Mozilla Firefox Multiple Vulnerabilities - August12 (Windows)");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027450");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55249");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027451");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-60.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-66.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser.");
  script_tag(name:"affected", value:"Mozilla Firefox version before 15.0 on Windows");
  script_tag(name:"insight", value:"- An error due to improper restriction of navigation to the about:newtab
    page, which allows remote attackers to execute arbitrary JavaScript code
    with chrome privileges via a crafted web site that triggers creation of a
    new tab and then a new window.

  - An error in the debugger in the developer-tools subsystem fails to
    restrict access to the remote-debugging service when remote debugging
    is disabled and the experimental HTTPMonitor extension has been installed
    and enabled.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 15.0 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"10.0")||
     version_in_range(version:ffVer, test_version:"11.0", test_version2:"14.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
