# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900894");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3978");
  script_name("Mozilla Firefox 'GIF' File DoS Vulnerability - Nov09 (Windows)");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=525326");
  script_xref(name:"URL", value:"https://wiki.mozilla.org/Releases/Firefox_3.5.5/Test_Plan");
  script_xref(name:"URL", value:"http://hg.mozilla.org/releases/mozilla-1.9.1/rev/edf189567edc");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attacker to cause a vulnerable
  application to crash.");

  script_tag(name:"affected", value:"Mozilla Firefox version prior to 3.5.5 on Windows.");

  script_tag(name:"insight", value:"A NULL pointer dereference error in 'nsGIFDecoder2::GifWrite' function in
  'decoders/gif/nsGIFDecoder2.cpp' in libpr0n, which can be exploited to cause
  application crash via an animated 'GIF' file with a large image size.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.5 or later.");

  script_tag(name:"summary", value:"Firefox browser is prone to Denial of Service vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"3.5.5")){
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"3.5.5");
  security_message(port: 0, data: report);
}
