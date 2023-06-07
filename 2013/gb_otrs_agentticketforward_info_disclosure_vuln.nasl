# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803929");
  script_version("2023-05-05T09:09:19+0000");
  script_cve_id("CVE-2010-4766");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-05-05 09:09:19 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2013-09-22 12:18:31 +0530 (Sun, 22 Sep 2013)");

  script_name("OTRS < 2.4.7 AgentTicketForward Information Disclosure Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote users to obtain
  potentially sensitive image information by reading a forwarded message from an e-mail client.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in AgentTicketForward feature which fails to
  remove inline images from HTML e-mail messages.");

  script_tag(name:"solution", value:"Update to version 2.4.7 or later.");

  script_tag(name:"summary", value:"OTRS (Open Ticket Request System) is prone to an information
  disclosure vulnerability.");

  script_tag(name:"affected", value:"OTRS versions prior to 2.4.7.");

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

if(version_is_less(version:vers, test_version:"2.4.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.7");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
