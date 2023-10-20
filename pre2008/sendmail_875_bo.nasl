# SPDX-FileCopyrightText: 2003 Xue Yong Zhi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sendmail:sendmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11347");
  script_version("2023-08-01T13:29:10+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/717");
  script_cve_id("CVE-1999-0131");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Sendmail Local Starvation and Overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Xue Yong Zhi");
  script_family("SMTP problems");
  script_dependencies("gb_sendmail_detect.nasl");
  script_mandatory_keys("sendmail/detected");

  script_tag(name:"solution", value:"Install sendmail newer than 8.8.3 or install a vendor
  supplied patch.");

  script_tag(name:"summary", value:"The remote sendmail server, according to its version number,
  has buffer overflow and denial of service problem through GECOS field, it gives root access to
  local users.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

# nb: Sendmail 8.6.*, 8.7, 8.7.1-8.7.5
if(vers =~ "^8\.(6|6\.[0-9]+|7|7\.[1-5])$") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"> 8.8.3");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);