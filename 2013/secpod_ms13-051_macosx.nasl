# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902977");
  script_version("2024-07-01T05:05:39+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-1331");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:39 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 14:18:56 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-06-12 09:30:35 +0530 (Wed, 12 Jun 2013)");
  script_name("Microsoft Office Remote Code Execution Vulnerability (2839571) - Mac OS X");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028650");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60408");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-051");

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code as
  the logged-on user.");

  script_tag(name:"affected", value:"Microsoft Office 2011 on Mac OS X.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing PNG files and can be exploited
  to cause a buffer overflow via a specially crafted file.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-051.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

offVer = get_kb_item("MS/Office/MacOSX/Ver");

if(!offVer || offVer !~ "^14\."){
  exit(0);
}

if(version_in_range(version:offVer, test_version:"14.0", test_version2:"14.3.4"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
