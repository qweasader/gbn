# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805757");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2015-7180", "CVE-2015-7177",
                "CVE-2015-7176", "CVE-2015-7175", "CVE-2015-7174", "CVE-2015-4522",
                "CVE-2015-4521", "CVE-2015-4520", "CVE-2015-4519", "CVE-2015-4517",
                "CVE-2015-4511", "CVE-2015-4509", "CVE-2015-4506", "CVE-2015-4500");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-09-29 18:11:28 +0530 (Tue, 29 Sep 2015)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities (Sep 2015) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are exists due to:

  - Failed to  restrict the availability of High Resolution Time API times,

  - Multiple memory corruption flaws,

  - 'js/src/proxy/Proxy.cpp' mishandles certain receiver arguments,

  - Multiple unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  and remote attackers to cause a denial of service or possibly execute arbitrary
  code, gain privileges and some unspecified impacts.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version 38.x before 38.3 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version
  38.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-114/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_in_range(version:ffVer, test_version:"38.0", test_version2:"38.2.1"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     ' + "38.3" + '\n';
  security_message(data:report);
  exit(0);
}
