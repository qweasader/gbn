###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome multiple vulnerabilities - May11 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801878");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-05-11 15:50:14 +0200 (Wed, 11 May 2011)");
  script_cve_id("CVE-2011-1303", "CVE-2011-1305", "CVE-2011-1434", "CVE-2011-1435",
                "CVE-2011-1437", "CVE-2011-1438", "CVE-2011-1440", "CVE-2011-1441",
                "CVE-2011-1442", "CVE-2011-1443", "CVE-2011-1445", "CVE-2011-1446",
                "CVE-2011-1447", "CVE-2011-1448", "CVE-2011-1449", "CVE-2011-1450",
                "CVE-2011-1451", "CVE-2011-1452", "CVE-2011-1454", "CVE-2011-1455",
                "CVE-2011-1456");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome multiple vulnerabilities - May11 (Windows)");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/04/chrome-stable-update.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47604");

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain security
  restrictions, disclose potentially sensitive information, conduct spoofing
  attacks, and potentially compromise a user's system.");
  script_tag(name:"affected", value:"Google Chrome version prior to 11.0.696.57 on Windows");
  script_tag(name:"insight", value:"- An unspecified error related to a stale pointer exists in handling
    of floating objects.

  - MIME handling does not properly ensure thread safety.

  - An extension with 'tabs' permission can gain access to local files.

  - An integer overflow error exists within the float rendering.

  - An error related to blobs can be exploited to violate the same origin
    policy.

  - A use-after-free error exists within the handling of '<ruby>' tags and CSS.

  - A casting error exists within then handling of floating select lists.

  - An error related to mutation events can be exploited to corrupt node trees.

  - An unspecified error related to stale pointers exists in the layering code.

  - Interrupted loads and navigation errors can be leveraged to spoof the URL
    bar.

  - An unspecified error related to a stale pointer exists within the handling
    of drop-down lists.

  - An unspecified error related to a stale pointer exists within the height
    calculations.

  - A use-after-free error exists within the handling of WebSockets.

  - An error related to dangling pointers exists within the handling of file
    dialogs.

  - An error related to dangling pointers exists within the handling of DOM
    id maps.

  - Redirects and manual reloads can be exploited to spoof the URL bar.

  - A use-after-free error exists within the handling of DOM ids.

  - An error related to stale pointers exists within the handling of PDF forms.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 11.0.696.57 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"11.0.696.57")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"11.0.696.57");
  security_message(port: 0, data: report);
}
