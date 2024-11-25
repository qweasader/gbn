# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900038");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-4195");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_name("Opera Web Browser Multiple Security Vulnerabilities (Aug 2008) - Windows");
  script_dependencies("smb_reg_service_pack.nasl", "gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");

  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/892/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30768");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/893/");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/894/");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/895/");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/896/");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/897/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/windows/952/");

  script_tag(name:"summary", value:"Opera is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Multiple vulnerabilities exist in the Opera Browser,

  - Sites can change framed content on other sites

  - Startup crash can allow execution of arbitrary code

  - Custom shortcuts can pass the wrong parameters to applications

  - Insecure pages can show incorrect security information

  - Feed links can link to local files

  - Feed subscription can cause the wrong page address to be displayed");

  script_tag(name:"affected", value:"Opera Version 9.51 and prior versions on Windows (All)");

  script_tag(name:"solution", value:"Upgrade to Opera version 9.52.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"impact", value:"Remote exploitation will allow browser to crash, can potentially
  execute arbitrary code, cross site scripting attacks, and can even change
  the address field to the address of the malicious web page to mislead a user.");

  exit(0);
}

if(!get_kb_item("SMB/WindowsVersion")){
    exit(0);
}

 if(egrep(pattern:"^([0-8]\..*|9\.([0-4]?[0-9]|5[01]))$",
      string:get_kb_item("Opera/Win/Version"))){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
 }

exit(99);
