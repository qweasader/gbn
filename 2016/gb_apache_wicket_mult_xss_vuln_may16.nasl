# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:wicket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807585");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2015-5347", "CVE-2015-7520");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-12 18:23:00 +0000 (Tue, 12 Feb 2019)");
  script_tag(name:"creation_date", value:"2016-05-16 10:44:34 +0530 (Mon, 16 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Wicket Multiple Cross-site scripting Vulnerabilities (May 2016)");

  script_tag(name:"summary", value:"Apache Wicket is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Insufficient validation of user supplied input via 'value' attribute
    in RadioGroup and CheckBoxMultipleChoice classes.

  - Insufficient validation of user supplied input via 'ModalWindow title'
    in getWindowOpenJavaScript function in
    org.apache.wicket.extensions.ajax.markup.html.modal.ModalWindow class.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Apache Wicket 1.5.x before 1.5.15,
  6.x before 6.22.0, and 7.x before 7.2.0.");

  script_tag(name:"solution", value:"Upgrade to Apache Wicket version 1.5.15 or
  6.22.0 or 7.2.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wicket.apache.org/news/2016/03/02/cve-2015-7520.html");
  script_xref(name:"URL", value:"http://wicket.apache.org/news/2016/03/01/cve-2015-5347.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_wicket_detect.nasl");
  script_mandatory_keys("Apache/Wicket/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wkPort = get_app_port(cpe:CPE)){
  exit(0);
}

wkVer = get_app_version(cpe:CPE, port:wkPort);

if(!wkVer || wkVer == "unknown"){
  exit(0);
}

if(version_is_less(version:wkVer, test_version:"1.5.15"))
{
  fix = "1.5.15";
  VULN = TRUE ;
}

else if(version_in_range(version:wkVer, test_version:"6.0", test_version2:"6.21.0"))
{
  fix = "6.22.0";
  VULN = TRUE ;
}

else if(version_in_range(version:wkVer, test_version:"7.0", test_version2:"7.1.0"))
{
  fix = "7.2.0";
  VULN = TRUE ;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:wkVer, fixed_version:fix);
  security_message(data:report, port:wkPort);
  exit(0);
}
exit(0);
