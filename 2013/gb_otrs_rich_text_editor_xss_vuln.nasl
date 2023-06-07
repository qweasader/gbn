# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803925");
  script_version("2023-05-05T09:09:19+0000");
  script_cve_id("CVE-2010-4762");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-05-05 09:09:19 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2013-09-21 23:18:31 +0530 (Sat, 21 Sep 2013)");

  script_name("OTRS < 3.0.0-beta2 Rich-text-editor XSS Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to
  inject arbitrary web script.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in rich-text-editor component which fails to
  validate user supplied input.");

  script_tag(name:"solution", value:"Update to version 3.0.0-beta2 or later.");

  script_tag(name:"summary", value:"OTRS (Open Ticket Request System) is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"affected", value:"OTRS versions prior to 3.0.0-beta2.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"3.0.0.beta2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.0.0.beta2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
