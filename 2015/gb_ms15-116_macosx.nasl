# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806705");
  script_version("2024-02-28T05:05:37+0000");
  script_cve_id("CVE-2015-6038", "CVE-2015-6094", "CVE-2015-6123");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-28 05:05:37 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-11-24 10:32:31 +0530 (Tue, 24 Nov 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Multiple Vulnerabilities (3104540) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-116");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Improper handling of files and objects in the memory.

  - Insufficient sanitization of user supplied input by Outlook for Mac.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, conduct spoofing attacks, perform unauthorized
  actions and some other attacks.");

  script_tag(name:"affected", value:"Microsoft Office 2011 on Mac OS X.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3102924");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77489");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77490");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-116");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

offVer = get_kb_item("MS/Office/MacOSX/Ver");

if(!offVer || offVer !~ "^14\."){
  exit(0);
}

if(version_in_range(version:offVer, test_version:"14.0", test_version2:"14.5.7"))
{
  report = 'File version:     ' + offVer   + '\n' +
           'Vulnerable range: 14.0 - 14.5.7' + '\n' ;
  security_message(data:report);
}
