# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801000");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0937");
  script_name("Visualization Library Multiple Unspecified Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55478");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37644");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0050");
  script_xref(name:"URL", value:"http://visualizationlibrary.com/documentation/pagchangelog.html");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_visualization_library_detect_win.nasl");
  script_mandatory_keys("VisualizationLibrary/Win/Ver");
  script_tag(name:"impact", value:"Unknown impacts and unknown attack vectors.");
  script_tag(name:"affected", value:"Visualization Library versions prior to 2009.08.812 on Windows");
  script_tag(name:"insight", value:"The flaws are caused by multiple unspecified errors with unknown impact and
  unknown attack vectors.");
  script_tag(name:"solution", value:"Update to version 2009.08.812 or above.");
  script_tag(name:"summary", value:"Visualization Library is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.visualizationlibrary.com/downloads.php");
  exit(0);
}


include("version_func.inc");

vslVer = get_kb_item("VisualizationLibrary/Win/Ver");
if(isnull(vslVer)){
  exit(0);
}

if(version_is_less(version:vslVer, test_version:"2009.08.812")){
  report = report_fixed_ver(installed_version:vslVer, fixed_version:"2009.08.812");
  security_message(port: 0, data: report);
}
