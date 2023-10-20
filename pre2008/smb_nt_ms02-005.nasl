# SPDX-FileCopyrightText: 2002 Michael Scheidell
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Also supersedes MS02-005, MS02-047, MS02-027, MS02-023, MS02-015, MS01-015

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10861");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0842", "CVE-2004-0727", "CVE-2004-0216", "CVE-2004-0839",
                "CVE-2004-0844", "CVE-2004-0843", "CVE-2004-0841", "CVE-2004-0845",
                "CVE-2003-0814", "CVE-2003-0815", "CVE-2003-0816", "CVE-2003-0817",
                "CVE-2003-0823", "CVE-2004-0549", "CVE-2004-0566", "CVE-2003-1048",
                "CVE-2001-1325", "CVE-2001-0149", "CVE-2001-0727", "CVE-2001-0875",
                "CVE-2001-0339", "CVE-2001-0002", "CVE-2002-0190", "CVE-2002-0026",
                "CVE-2003-1326", "CVE-2002-0027", "CVE-2002-0022", "CVE-2003-1328",
                "CVE-2002-1262", "CVE-2002-0193", "CVE-1999-1016", "CVE-2003-0344",
                "CVE-2003-0233", "CVE-2003-0309", "CVE-2003-0113", "CVE-2003-0114",
                "CVE-2003-0115", "CVE-2003-0116", "CVE-2003-0531", "CVE-2003-0809",
                "CVE-2003-0530", "CVE-2003-1025", "CVE-2003-1026", "CVE-2003-1027",
                "CVE-2005-0553", "CVE-2005-0554", "CVE-2005-0555");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"IAVA", value:"2003-A-0014");
  script_xref(name:"IAVA", value:"2004-A-0016");
  script_xref(name:"IAVA", value:"2005-A-0006");
  script_name("IE 5.01 5.5 6.0 Cumulative patch (890923)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michael Scheidell");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "global_settings.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"The July 2004 Cumulative Patch for IE is not applied on the remote host.");

  script_tag(name:"impact", value:"Run code of attacker's choice.");

  script_tag(name:"solution", value:"The vendor has released updates, please see the references for more information.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2005/ms05-020");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10473");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11366");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11367");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11377");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11381");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11383");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11385");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11388");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12473");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12475");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12477");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12530");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13117");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13123");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8565");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9009");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9012");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9013");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9014");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9015");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9182");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9663");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9798");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

# 883939 supersedes MS05-020
if ( hotfix_missing(name:"883939.*") == 0 &&
     "883939" >!<  get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion") ) exit(0);

if ( hotfix_check_sp(nt:7, xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

version = get_kb_item("SMB/WindowsVersion");
if(version)
{
 value = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/Version");
 if ( value )
  {
   minorversion = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion");
   report = string("The remote host is running IE Version ",value);
   if(minorversion)
   {
    if ( hotfix_missing(name:"890923.*") == 0 ) exit(0);
    if ( "890923" >!< minorversion ) missing = "890923 (MS05-020)";
   }
   else if ( hotfix_missing(name:"890923.*") > 0 )
     missing = "890923 (MS05-020)";
   else exit(0);

   report += '\nHowever is it missing Microsoft Hotfix ' + missing + '\n';
   report += 'Solution: http://www.microsoft.com/technet/security/bulletin/ms05-020.mspx\nRisk Factor : High\n';

   if( missing ) security_message(port:0, data:report);
  }
}
