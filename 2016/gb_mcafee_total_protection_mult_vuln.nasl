###############################################################################
# OpenVAS Vulnerability Test
#
# McAfee Total Protection Multiple Vulnerabilities (Windows)
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

CPE = "cpe:/a:mcafee:total_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807237");
  script_version("2022-05-25T07:40:23+0000");
  script_cve_id("CVE-2015-8772", "CVE-2015-8773");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-05-25 07:40:23 +0000 (Wed, 25 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-04 18:03:00 +0000 (Fri, 04 Mar 2016)");
  script_tag(name:"creation_date", value:"2016-02-08 17:22:31 +0530 (Mon, 08 Feb 2016)");
  script_name("McAfee Total Protection Multiple Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"McAfee Total Protection is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The McAfee File Lock Driver does not handle correctly IOCTL_DISK_VERIFY
    IOCTL requests.

  - The McAfee File Lock Driver does not handle correctly GUIDs of the encrypted
    vaults.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to disclose sensitive information from kernel memory or crash the affected host.");

  script_tag(name:"affected", value:"McAfee Total Protection kernel driver
  module 'McPvDrv.sys' version 4.6.111.0 and probably earlier.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.nettitude.co.uk/mcafee-file-lock-driver-kernel-memory-leak");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82143");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82144");
  script_xref(name:"URL", value:"https://www.nettitude.co.uk/mcafee-file-lock-driver-kernel-stack-based-bof");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mcafee_total_protection_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("McAfee/TotalProtection/Win/Ver");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Drivers\McPvDrv.sys");
if(!sysVer){
  exit(0);
}

if(version_is_less_equal(version:sysVer, test_version:"4.6.111.0"))
{
  report = report_fixed_ver(installed_version:sysVer, fixed_version: "None Available");
  security_message(data:report);
  exit(0);
}

