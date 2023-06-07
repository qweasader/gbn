###############################################################################
# OpenVAS Vulnerability Test
#
# F-PROT AV 'ELF' Header Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800325");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-01-13 15:40:34 +0100 (Tue, 13 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5747");
  script_name("F-PROT AV 'ELF' Header Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://securityreason.com/securityalert/4822");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32753");
  script_xref(name:"URL", value:"http://www.ivizsecurity.com/security-advisory-iviz-sr-08016.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_f-prot_av_detect_lin.nasl");
  script_mandatory_keys("F-Prot/AV/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass anti-virus protection
  and cause a Denial of Service condition.");
  script_tag(name:"affected", value:"Frisk Software, F-Prot Antivirus version 4.6.8 and prior on Linux.");
  script_tag(name:"insight", value:"The flaw is due to error in ELF program with a corrupted header. The
  scanner can be exploited while scanning the header.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to F-Prot Antivirus version 6.0.2 or later.");
  script_tag(name:"summary", value:"F-PROT Antivirus is prone to a denial of service vulnerability.");

  exit(0);
}

include("version_func.inc");

fpscanVer = get_kb_item("F-Prot/AV/Linux/Ver");
if(!fpscanVer){
  exit(0);
}

if(version_is_less_equal(version:fpscanVer, test_version:"4.6.8")){
  report = report_fixed_ver(installed_version:fpscanVer, vulnerable_range:"Less than or equal to 4.6.8");
  security_message(port: 0, data: report);
}
