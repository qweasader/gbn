# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902382");
  script_version("2022-02-17T14:14:34+0000");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_cve_id("CVE-2011-1801", "CVE-2011-1804", "CVE-2011-1806", "CVE-2011-1807");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome Multiple Vulnerabilities May11 (Windows)");
  script_xref(name:"URL", value:"http://trac.webkit.org/changeset/86862");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/05/stable-channel-update_24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");

  script_tag(name:"affected", value:"Google Chrome version prior to 11.0.696.71 on windows.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in 'Pop-up' blocker bypass,

  - An error in 'rendering/RenderBox.cpp' in WebCore in 'WebKit', which fails
    to properly render floats and results in stale pointer,

  - A memory corruption error in GPU command buffer and

  - A out-of-bounds write error in 'blob' handling.");

  script_tag(name:"solution", value:"Update to Google Chrome version 11.0.696.71 or later.");

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

if(version_is_less(version:chromeVer, test_version:"11.0.696.71")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"11.0.696.71");
  security_message(port: 0, data: report);
}
