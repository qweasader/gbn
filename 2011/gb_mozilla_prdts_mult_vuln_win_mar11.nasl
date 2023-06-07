###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products Multiple Vulnerabilities March-11 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801902");
  script_version("2022-02-28T15:36:21+0000");
  script_tag(name:"last_modification", value:"2022-02-28 15:36:21 +0000 (Mon, 28 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_cve_id("CVE-2011-0051", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056",
                "CVE-2011-0057", "CVE-2011-0058", "CVE-2011-0059");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities (mfsa2011-02, mfsa2011-03, mfsa2011-04, mfsa2011-05, mfsa2011-06, mfsa2011-07) - Windows");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0531");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-02.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-03.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-04.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-05.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-06.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-07.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service or
  execute arbitrary code or hijack the authentication of arbitrary users.");
  script_tag(name:"affected", value:"Seamonkey version before 2.0.12
  Firefox version before 3.5.17 and 3.6.x before 3.6.14");
  script_tag(name:"insight", value:"The flaws are due to:

  - An error when handling a recursive call to 'eval()' wrapped in a try or
     catch statement, which could be exploited to force a user into accepting
     any dialog.

  - A buffer overflow error related to the JavaScript engine's internal memory
     mapping of non-local JS variables, which could allow attackers to execute
     arbitrary code.

  - A user-after-free error related to a method used by 'JSON.stringify', which
     could allow attackers to execute arbitrary code.

  - A buffer overflow error related to the JavaScript engine's internal memory
     mapping of string values, which could allow attackers to execute arbitrary
     code.

  - An use-after-free error related to Web Workers, which could allow attackers
     to execute arbitrary code.

  - A cross-site request forgery (CSRF) vulnerability, allows remote attackers
     to hijack the authentication of arbitrary users for requests that were
     initiated by a plugin and received a 307 redirect to a page on a different
     web site.");
  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey are prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.17 or 3.6.14 or later,
  Upgrade to Seamonkey version 2.0.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.5.17") ||
     version_in_range(version:vers, test_version:"3.6.0", test_version2:"3.6.13"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  if(version_is_less(version:smVer, test_version:"2.0.12")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
