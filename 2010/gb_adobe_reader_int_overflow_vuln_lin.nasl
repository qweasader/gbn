###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader Font Parsing Integer Overflow Vulnerability (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.801420");
  script_version("2022-02-28T15:36:21+0000");
  script_tag(name:"last_modification", value:"2022-02-28 15:36:21 +0000 (Mon, 28 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2862");
  script_name("Adobe Reader Font Parsing Integer Overflow Vulnerability (CVE-2010-2862) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40766");
  script_xref(name:"URL", value:"http://www.zdnet.co.uk/news/security-threats/2010/08/04/adobe-confirms-pdf-security-hole-in-reader-40089737/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation results in memory corruption via a PDF
file containing a specially crafted TrueType font.");
  script_tag(name:"affected", value:"Adobe Reader version 8.2.3 and 9.3.3");
  script_tag(name:"insight", value:"The flaw is due to an integer overflow error in 'CoolType.dll'
when parsing the 'maxCompositePoints' field value in the 'maxp' (Maximum Profile)
table of a TrueType font.");
  script_tag(name:"solution", value:"Upgrade to version 8.2.4 or 9.3.4 or later.");
  script_tag(name:"summary", value:"Adobe Reader are prone to a font parsing integer overflow vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

readerVer = get_kb_item("Adobe/Reader/Linux/Version");

if(readerVer != NULL)
{
  if(version_is_equal(version:readerVer, test_version:"8.2.3") ||
     version_is_equal(version:readerVer, test_version:"9.3.3")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
