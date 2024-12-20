# SPDX-FileCopyrightText: 2003 Jeff Adams
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11886");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"IAVA", value:"2003-B-0006");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0660");
  script_name("Vulnerability in Authenticode Verification Could Allow Remote Code Execution (823182)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Jeff Adams");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"There is a vulnerability in Authenticode that, under certain low memory
  conditions, could allow an ActiveX control to download and install without presenting the user with an approval dialog.");

  script_tag(name:"impact", value:"Exploiting the vulnerability would grant the attacker with the same privileges
  as the user.");

  script_tag(name:"insight", value:"To exploit this vulnerability, an attacker could host a malicious Web Site designed
  to exploit this vulnerability. If an attacker then persuaded a user to visit that site an ActiveX control could be
  installed and executed on the user's system. Alternatively, an attacker could create a specially formed HTML e-mail and
  send it to the user.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-041");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8830");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB823182") > 0 )
  security_message(port:0);
