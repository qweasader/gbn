# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.903032");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2011-3103", "CVE-2011-3104", "CVE-2011-3105", "CVE-2011-3106",
                "CVE-2011-3107", "CVE-2011-3108", "CVE-2011-3110", "CVE-2011-3111",
                "CVE-2011-3112", "CVE-2011-3113", "CVE-2011-3114", "CVE-2011-3115");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-05-25 16:25:17 +0530 (Fri, 25 May 2012)");
  script_name("Google Chrome Multiple Vulnerabilities(02) - May 12 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49277/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53679");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027098");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/05/stable-channel-update_23.html");

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 19.0.1084.52 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to

  - An unspecified error exists in the v8 garbage collection, plug-in
    JavaScript bindings.

  - A use-after-free error exists in the browser cache, first-letter handling
    and with encrypted PDF.

  - An out-of-bounds read error exists in Skia.

  - An error with websockets over SSL can be exploited to corrupt memory.

  - An invalid read error exists in v8.

  - An invalid cast error exists with colorspace handling in PDF.

  - An error with PDF functions can be exploited to cause a buffer overflow.

  - A type corruption error exists in v8.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 19.0.1084.52 or later.");
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

if(version_is_less(version:chromeVer, test_version:"19.0.1084.52")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"19.0.1084.52");
  security_message(port:0, data:report);
}
