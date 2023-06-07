# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902025");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_cve_id("CVE-2010-1029", "CVE-2010-1939");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Apple Safari multiple vulnerabilities (Mar10)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39670");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38398");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39990");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56524");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56527");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11567");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1097");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/May/1023958.html");

  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to send a
  malformed CSS stylesheet tag containing an overly long string, which leads to
  application crash or possibly execute arbitrary code on the system.");

  script_tag(name:"affected", value:"Apple Safari version 4.0.5 and lower.");

  script_tag(name:"insight", value:"The flaws are caused by,

  - Error in the 'CSSSelector()' function when handling CSS stylesheet tag
   containing an overly long string.

  - Improper bounds checking by the 'WebKit' library when processing CSS
   stylesheet tag containing an overly long string.

  - Use-after-free error when handling of a deleted window object, allows attackers
   to execute arbitrary code by using 'window.open' to create a popup window for
   a crafted HTML document, and then calling the parent window&qts close method.

  - Includes HTTP basic authentication credentials in an HTTP request if a web page
   that requires HTTP basic authentication redirects to a different domain.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 5.0 or later.");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

## Included version 4.0.5 because exploit is working
if(version_is_less_equal(version:vers, test_version:"5.31.22.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 5.0 (output of installed version differ from actual Safari version)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
