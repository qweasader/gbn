# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:informix_dynamic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808639");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-0226");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:16:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-08-08 13:44:37 +0530 (Mon, 08 Aug 2016)");
  script_name("IBM Informix Dynamic Server Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"IBM Informix Dynamic Server is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper restrict
  access to the 'nsrd', 'nsrexecd', and 'portmap' executable files in client
  implementation.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  users to modify the binary for this service and thus execute code in the
  context of SYSTEM.");

  script_tag(name:"affected", value:"IBM Informix Dynamic Server 11.70.xCn
  on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=630&uid=swg21978598");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85198");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("secpod_ibm_informix_dynamic_server_detect_win.nasl");
  script_mandatory_keys("IBM/Informix/Dynamic/Server/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

idsVer = get_app_version(cpe:CPE);
if(!idsVer){
  exit(0);
}

if(version_is_equal(version:idsVer, test_version:"11.70"))
{
  report = report_fixed_ver(installed_version:idsVer, fixed_version:"Apply the patch");
  security_message(data:report);
  exit(0);
}
