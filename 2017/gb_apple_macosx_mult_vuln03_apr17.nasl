###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X Multiple Vulnerabilities-03 April-2017
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810931");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2010-0543", "CVE-2010-1375");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-04-18 11:40:44 +0530 (Tue, 18 Apr 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-03 April-2017");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A memory corruption exists in the handling of MPEG2 encoded movie files.

  - NetAuthSysAgent does not require authorization for certain operations.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to cause an unexpected application termination or arbitrary code execution and
  escalate privileges.");

  script_tag(name:"affected", value:"Apple Mac OS X and Mac OS X Server
  version 10.5.8");

  script_tag(name:"solution", value:"Apply the appropriate patch from the
  referenced link.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod", value:"30"); ## Build information is not available

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT4188");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40894");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40901");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.5");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
  exit(0);
}

if("Mac OS X" >< osName)
{
  ## 10.5.8 prior to build X is also vulnerable.
  if(version_in_range(version:osVer, test_version:"10.5", test_version2:"10.5.8"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"Apply the appropriate patch");
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
