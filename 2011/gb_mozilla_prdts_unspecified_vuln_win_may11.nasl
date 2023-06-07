###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products Unspecified Vulnerability May-11 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801887");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_cve_id("CVE-2011-0081");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Unspecified Vulnerability May-11 (Windows)");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1127");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47653");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=645289");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-12.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to a cause a denial of
  service or possibly execute arbitrary code.");
  script_tag(name:"affected", value:"Thunderbird 3.1.x before 3.1.10
  Mozilla Firefox versions 3.6.x before 3.6.17 and 4.x before 4.0.1");
  script_tag(name:"insight", value:"The flaw is due to unspecified vulnerability in the browser engine
  which allows remote attackers to cause a denial of service or possibly
  execute arbitrary code via unknown vectors.");
  script_tag(name:"summary", value:"Mozilla Firefox or Thunderbird is prone to an unspecified vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.17, 4.0.1 or later,
  Upgrade to Thunderbird version 3.1.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");


vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_in_range(version:vers, test_version:"3.6.0", test_version2:"3.6.16") ||
     version_in_range(version:vers, test_version:"4.0", test_version2:"4.0.b12")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.9")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
