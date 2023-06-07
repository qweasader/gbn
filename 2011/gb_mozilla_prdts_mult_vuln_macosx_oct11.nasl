###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products Multiple Vulnerabilities - Oct 2011 (MAC OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802180");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-3000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities - Oct 2011 (MAC OS X)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46171/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49810");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49811");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49849");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-40.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-36.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-39.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to bypass intended access
  restrictions via a crafted web site and cause a denial of service
  (memory corruption and application crash) or possibly execute arbitrary
  code via unknown vectors.");
  script_tag(name:"affected", value:"SeaMonkey version prior to 2.4
  Thunderbird version prior to 7.0
  Mozilla Firefox version prior to 3.6.23 and 4.x through 6");
  script_tag(name:"insight", value:"The flaws are due to

  - A malicious application or extension could be downloaded and executed if a
    user is convinced into holding down the 'Enter' key via e.g. a malicious
    game.

  - Some unspecified errors can be exploited to corrupt memory.

  - Error while handling HTTP responses that contain multiple Location,
    Content-Length, or Content-Disposition headers, which allows remote
    attackers to conduct HTTP response splitting attacks via crafted header
    values.");
  script_tag(name:"summary", value:"Mozilla firefox/thunderbird/seamonkey is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.23 or 7 later, Upgrade to SeaMonkey version to 2.4 or later,
  Upgrade to Thunderbird version to 7.0 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.6.23")||
     version_in_range(version:vers, test_version:"4.0", test_version2:"6.0"))
  {
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
  }
}

vers = get_kb_item("SeaMonkey/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"2.4"))
  {
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
  }
}

vers = get_kb_item("Thunderbird/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"7.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
