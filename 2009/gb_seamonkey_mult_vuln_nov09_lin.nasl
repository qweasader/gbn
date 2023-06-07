###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Seamonkey Multiple Vulnerabilities Nov-09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801137");
  script_version("2022-09-20T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-20 10:11:40 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"creation_date", value:"2009-11-04 07:03:36 +0100 (Wed, 04 Nov 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3376");
  script_name("Mozilla Seamonkey Multiple Vulnerabilities Nov-09 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-35/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36855");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36856");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36867");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-55.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-56.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-62.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_seamonkey_detect_lin.nasl");
  script_mandatory_keys("Seamonkey/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attacker to disclose sensitive information,
  bypass certain security restrictions, manipulate certain data, or compromise
  a user's system.");
  script_tag(name:"affected", value:"Mozilla Seamonkey version prior to 2.0 on Linux.");
  script_tag(name:"insight", value:"Multiple flaws exist:

  - When parsing regular expressions used in Proxy Auto-configuration. This can
    be exploited to cause a crash or potentially execute arbitrary code via
    specially crafted configured PAC files.

  - When processing GIF color maps which can be exploited to cause a heap based
    buffer overflow and potentially execute arbitrary code via a specially
    crafted GIF file.

  - An error when downloading files can be exploited to display different file
    names in the download dialog title bar and download dialog body. This can
    be exploited to obfuscate file names via a right-to-left override character
    and potentially trick a user into running an executable file.");
  script_tag(name:"solution", value:"Upgrade to Seamonkey version 2.0.");
  script_tag(name:"summary", value:"Mozilla Seamonkey is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

smVer = get_kb_item("Seamonkey/Linux/Ver");
if(!smVer)
  exit(0);

if(version_is_less(version:smVer, test_version:"2.0")){
  report = report_fixed_ver(installed_version:smVer, fixed_version:"2.0");
  security_message(port: 0, data: report);
}
