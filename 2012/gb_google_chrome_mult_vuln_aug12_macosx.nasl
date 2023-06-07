###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities - August 12 (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802929");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-2847", "CVE-2012-2860", "CVE-2012-2858", "CVE-2012-2857",
                "CVE-2012-2856", "CVE-2012-2855", "CVE-2012-2854", "CVE-2012-2853",
                "CVE-2012-2852", "CVE-2012-2851", "CVE-2012-2850", "CVE-2012-2849",
                "CVE-2012-2848");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-08-08 15:15:33 +0530 (Wed, 08 Aug 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - August 12 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50105/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54749");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/07/stable-channel-release.html");

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 21.0.1180.57 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to

  - The application does not properly re-prompt the user when downloading
    multiple files and can be exploited to trick the user into downloading a
    malicious file.

  - An error when handling drag and drop events.

  - Integer overflow errors, use-after-free error, out-of-bounds write error
    exists within the PDF viewer.

  - A use-after-free error exists when handling object linkage in PDFs.

  - An error within the 'webRequest' module can be exploited to cause
    interference with the Chrome Web Store.

  - A use-after-free error exits when handling CSS DOM objects.

  - An error within the WebP decoder can be exploited to cause a buffer
    overflow.

  - An out-of-bounds access error exists when clicking in date picker.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 21.0.1180.57 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"21.0.1180.57")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"21.0.1180.57");
  security_message(port:0, data:report);
}
