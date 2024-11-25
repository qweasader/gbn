# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902546");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_cve_id("CVE-2011-1033");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("IBM Informix Dynamic Server Oninit Remote Code Execution Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43212");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46230");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65209");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-11-050/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_ibm_informix_dynamic_server_detect_win.nasl");
  script_mandatory_keys("IBM/Informix/Dynamic/Server/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM-level privileges.");
  script_tag(name:"affected", value:"IBM Informix Dynamic Server (IDS) version 11.50");
  script_tag(name:"insight", value:"The flaw is due to a boundary error in the oninit process bound to TCP
  port 9088 when processing the arguments to the USELASTCOMMITTED option in a
  SQL query.");
  script_tag(name:"solution", value:"Upgrade to IBM Informix IDS version 11.50.xC8 or later.");
  script_tag(name:"summary", value:"IBM Informix Dynamic Server is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

version = get_kb_item("IBM/Informix/Dynamic/Server/Win/Ver");
if(version)
{
  if(version_is_equal(version:version, test_version:"11.50")){
    report = report_fixed_ver(installed_version:version, vulnerable_range:"Equal to 11.50");
    security_message(port: 0, data: report);
  }
}
