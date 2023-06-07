###############################################################################
# OpenVAS Vulnerability Test
#
# Nuance PDF Reader Multiple Memory Corruption Vulnerabilities
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803329");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-0113");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-03-11 15:51:39 +0530 (Mon, 11 Mar 2013)");
  script_name("Nuance PDF Reader Multiple Memory Corruption Vulnerabilities");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/248449");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57851");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/438057.php");
  script_xref(name:"URL", value:"http://secunia.com/advisories/cve_reference/CVE-2013-0113");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_dependencies("gb_nuance_pdf_reader_detect_win.nasl");
  script_mandatory_keys("Nuance/PDFReader/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows an attacker to corrupt memory, execute
arbitrary code within the context of the user running the affected
application or failed attempts may cause a denial-of-service.");
  script_tag(name:"affected", value:"Nuance PDF Reader version 7.0");
  script_tag(name:"insight", value:"Multiple unspecified flaws as user input is not properly
sanitized when handling PDF files.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Nuance PDF Reader is prone to multiple memory-corruption vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


ReaderVer = get_kb_item("Nuance/PDFReader/Win/Ver");

if(ReaderVer && ReaderVer == "7.00.0000")
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
