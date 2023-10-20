# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804850");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2013-1862", "CVE-2013-1896", "CVE-2014-1256", "CVE-2014-1265",
                "CVE-2014-1259", "CVE-2013-6629", "CVE-2013-5986", "CVE-2013-5987",
                "CVE-2013-4073", "CVE-2013-4113", "CVE-2013-4248", "CVE-2013-6420",
                "CVE-2014-1246", "CVE-2014-1247", "CVE-2014-1248", "CVE-2014-1249",
                "CVE-2014-1250", "CVE-2014-1245");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-22 15:50:08 +0530 (Mon, 22 Sep 2014)");

  script_name("Apple Mac OS X Multiple Vulnerabilities -04 Sep14");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct cross-site scripting, change the system clock, bypass security
  restrictions, disclose sensitive information, compromise the affected system,
  and denial of service attacks.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.7.x through
  10.7.5, 10.8.x through 10.8.5 and 10.9.x before 10.9.2");

  script_tag(name:"solution", value:"Run Mac Updates. Please see the references for more information.");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6150");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59826");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60843");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61128");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61129");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61776");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63676");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64225");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64525");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65208");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65777");
  script_tag(name:"qod", value:"30"); ## Build information is not available
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6150");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54960");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[7-9]\.");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName)
{
  if(version_in_range(version:osVer, test_version:"10.9.0", test_version2:"10.9.1")||
     version_in_range(version:osVer, test_version:"10.8.0", test_version2:"10.8.5")||
     version_in_range(version:osVer, test_version:"10.7.0", test_version2:"10.7.5"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
  exit(99);
}

exit(0);
