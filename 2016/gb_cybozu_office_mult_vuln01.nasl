###############################################################################
# OpenVAS Vulnerability Test
#
# Cybozu Office Multiple Vulnerabilities-01 Feb16
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:cybozu:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807276");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-1153", "CVE-2016-1152", "CVE-2016-1151", "CVE-2015-8489",
                "CVE-2015-8486", "CVE-2015-8485", "CVE-2015-8484");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:26:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-03-03 18:23:55 +0530 (Thu, 03 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cybozu Office Multiple Vulnerabilities-01 Feb16");

  script_tag(name:"summary", value:"Cybozu Office is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in 'customapp' function.

  - An error in multiple functions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial-of-service, view the information about the
  groupware, obtain privileged information or cause specific functions to
  become unusable.");

  script_tag(name:"affected", value:"Cybozu Office version 9.9.0 to 10.3.0");
  script_tag(name:"solution", value:"Upgrade to Cybozu Office version 10.4.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN20246313/index.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83288");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83287");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83284");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN48720230/index.html");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN64209269/index.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_cybozu_products_detect.nasl");
  script_mandatory_keys("CybozuOffice/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!cybPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!cybVer = get_app_version(cpe:CPE, port:cybPort)){
  exit(0);
}

if(version_in_range(version:cybVer, test_version:"9.9.0", test_version2:"10.3.0"))
{
  report = report_fixed_ver(installed_version:cybVer, fixed_version:"10.4.0");
  security_message(data:report, port:cybPort);
  exit(0);
}

exit(99);
