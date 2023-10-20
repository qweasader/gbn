# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805433");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-0427", "CVE-2014-6595", "CVE-2014-6590", "CVE-2014-6589",
                "CVE-2014-6588");
  script_tag(name:"cvss_base", value:"3.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-02-02 10:11:39 +0530 (Mon, 02 Feb 2015)");
  script_name("Oracle Virtualbox Multiple Vulnerabilities Feb15 (Linux)");

  script_tag(name:"summary", value:"Oracle VM virtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to cause a DoS (Denial of Service) and disclose potentially
  sensitive information.");

  script_tag(name:"affected", value:"VirtualBox versions 4.3.x before 4.3.20
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version
  4.3.20 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.scip.ch/en/?vuldb.68800");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72216");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72206");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72213");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72202");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72196");
  script_xref(name:"URL", value:"http://secunia.com/advisories/62524");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(virtualVer =~ "^(4\.3)")
{
  if(version_is_less(version:virtualVer, test_version:"4.3.20"))
  {
    report = 'Installed version: ' + virtualVer + '\n' +
             'Fixed version:     ' + "4.3.20"  + '\n';
    security_message(data:report);
    exit(0);
  }
}
