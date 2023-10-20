# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:shockwave_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805926");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-5120", "CVE-2015-5121");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-16 12:33:59 +0530 (Thu, 16 Jul 2015)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities -01 July15 (Mac OS X)");

  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to some unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack and potentially execute arbitrary
  code in the context of the affected user.");

  script_tag(name:"affected", value:"Adobe Shockwave Player version before
  12.1.9.159 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version
  12.1.9.159 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/shockwave/apsb15-17.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Shockwave/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"12.1.9.159"))
{
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "12.1.9.159" + '\n';
  security_message(data:report);
  exit(0);
}
