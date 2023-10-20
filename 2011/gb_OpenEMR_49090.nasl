# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103193");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-10 15:25:18 +0200 (Wed, 10 Aug 2011)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("OpenEMR Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49090");
  script_xref(name:"URL", value:"http://www.open-emr.org/");

  script_tag(name:"summary", value:"OpenEMR is prone to multiple cross-site scripting vulnerabilities
  because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"OpenEMR is prone to multiple cross-site scripting vulnerabilities
  because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"affected", value:"OpenEMR 4.0.0 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are
  to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = 'cpe:/a:open-emr:openemr';

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(port:port, cpe:CPE))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"4.0.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"WillNotFix");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);