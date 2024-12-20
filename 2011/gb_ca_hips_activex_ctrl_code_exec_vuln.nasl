# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801858");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_cve_id("CVE-2011-1036");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_name("CA Host-Based Intrusion Prevention System 'XMLSecDB' ActiveX Control Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_ca_mult_prdts_detect_win.nasl");
  script_mandatory_keys("CA/Multiple_Products/Win/Installed");

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-093");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46539");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary
  code in the context of the logged-in user. Failed exploits result in denial-of-service conditions.");

  script_tag(name:"affected", value:"CA Internet Security Suite (ISS) 2010

  CA Internet Security Suite (ISS) 2011

  CA Host-Based Intrusion Prevention System (HIPS) r8.1");

  script_tag(name:"insight", value:"The flaw is caused by a design error in the XMLSecDB ActiveX
  control installed with the HIPSEngine component, which could allow attackers
  to create arbitrary files on a vulnerable system by tricking a user into
  visiting a web page which calls the 'SetXml()' and 'Save()' methods.");

  script_tag(name:"summary", value:"CA Host-Based Intrusion Prevention System(HIPS) is prone to a remote code-execution vulnerability.");

  script_tag(name:"solution", value:"Vendor has released a patch to fix this issue.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if(ver = get_kb_item("CA/HIPS/Server/Win/Ver"))
{
  if(version_is_less(version:ver, test_version:"8.1.0.88"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## CA Internet Security Suite (ISS)
if((hipsVer = get_kb_item("CA/HIPS/Engine/Win/Ver")) &&
   (issVer = get_kb_item("CA/ISS/Win/Ver")))
{
  ## CA Internet Security Suite (ISS) 2010:
  if(version_in_range(version:issVer, test_version:"6.0", test_version2:"6.0.0.285") &&
     version_is_less_equal(version:hipsVer, test_version:"1.6.384")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }

  ## CA Internet Security Suite (ISS) 2011:
  else if(version_in_range(version:issVer, test_version:"7.0", test_version2:"7.0.0.115") &&
     version_is_less_equal(version:hipsVer, test_version:"1.6.418")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
