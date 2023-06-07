###############################################################################
# OpenVAS Vulnerability Test
#
# Google SketchUp Multiple Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800435");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-01-20 08:21:11 +0100 (Wed, 20 Jan 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0316", "CVE-2010-0280");
  script_name("Google SketchUp < 7.1 M2 Multiple Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_sketchup_detect_win.nasl");
  script_mandatory_keys("Google/SketchUp/Win/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38185");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37708");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38187/3/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0133");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/google-sketchup-vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code and can cause Denial of Service.");

  script_tag(name:"affected", value:"Google SketchUp version 7.0 before 7.1 M2 (7.1.6860.0).");

  script_tag(name:"insight", value:"The flaws exist due to:

  - An array indexing error when processing '3DS' files which can be exploited to corrupt memory.

  - An integer overflow error when processing 'SKP' files which can be exploited to corrupt heap
  memory.");

  script_tag(name:"solution", value:"Update to version 7.1 M2 or later.");

  script_tag(name:"summary", value:"Google SketchUp is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("Google/SketchUp/Win/Ver"))
  exit(0);

if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.1.6859")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"7.0 - 7.1.6859");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
