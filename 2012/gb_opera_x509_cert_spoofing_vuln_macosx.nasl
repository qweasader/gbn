###############################################################################
# OpenVAS Vulnerability Test
#
# Opera 'X.509' Certificates Spoofing Vulnerability (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802437");
  script_version("2022-02-15T13:40:32+0000");
  script_cve_id("CVE-2012-1251");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-02-15 13:40:32 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2012-06-12 16:35:11 +0530 (Tue, 12 Jun 2012)");
  script_name("Opera 'X.509' Certificates Spoofing Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN39707339/index.html");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/mac/963/");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000049.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_mandatory_keys("Opera/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to spoof servers and
  obtain sensitive information.");
  script_tag(name:"affected", value:"Opera version prior to 9.63 on Mac OS X");
  script_tag(name:"insight", value:"The flaw is due to an error in handling of certificates, It does not properly
  verify 'X.509' certificates from SSL servers.");
  script_tag(name:"solution", value:"Upgrade to Opera 9.63 or later.");
  script_tag(name:"summary", value:"Opera is prone to spoofing vulnerability");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"9.63")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"9.63");
  security_message(port:0, data:report);
}
