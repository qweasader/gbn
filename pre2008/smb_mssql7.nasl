# SPDX-FileCopyrightText: 2001 Intranode <plugin@intranode.com>
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Should also cover BID:4135/CVE-2002-0056

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10642");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2002-0642");
  script_xref(name:"IAVA", value:"2002-B-0004");
  script_name("SMB Registry : SQL7 Patches");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Intranode <plugin@intranode.com>");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"solution", value:"The vendor has releases updates, please see the references for more information.");

  script_xref(name:"URL", value:"http://support.microsoft.com/default.aspx?scid=kb;en-us;256052");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5205");
  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/1/285915");
  script_xref(name:"URL", value:"http://online.securityfocus.com/advisories/4308");

  script_tag(name:"summary", value:"The remote SQL server seems to be vulnerable to the
  SQL abuse vulnerability described in technet article Q256052.");

  script_tag(name:"impact", value:"This problem allows an attacker who has to ability
  to execute SQL queries on this host to gain elevated privileges.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#


function check_key(key)
{
 item = "AllowInProcess";
 value = registry_get_dword(key:key, item:item);
 if(value != NULL && strlen(value) == 4)
 {
   item = "DisallowAdHocAccess";
   value = registry_get_dword(key:key, item:item);
   if((strlen(value)) == 0)
   {
     return(1);
   }
   else if(ord(value[0]) == 0)return(1);
 }
 return(0);
}


a = check_key(key:"SOFTWARE\Microsoft\MSSQLServer\Providers\MSDAORA");
if(a){security_message(port);exit(0);}
b = check_key(key:"SOFTWARE\Microsoft\MSSQLServer\Providers\MSDASQL");
if(b){security_message(port);exit(0);}
c = check_key(key:"SOFTWARE\Microsoft\MSSQLServerProviders\SQLOLEDB");
if(c){security_message(port);exit(0);}
d = check_key(key:"SOFTWARE\Microsoft\MSSQLServerProviders\Microsoft.Jet.OLEDB.4.0");
if(d){security_message(port);exit(0);}
