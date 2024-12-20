# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810264");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-06 13:28:45 +0530 (Fri, 06 Jan 2017)");
  script_name("Kaspersky Anti-Virus Local CA Root Security Bypass Vulnerability");

  script_tag(name:"summary", value:"Kaspersky Anti-Virus products are prone to a security bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the private key generated by Kaspersky for
  the local root is incorrectly protected.");

  script_tag(name:"impact", value:"Successful exploitation would allow remote attackers to escalate
  privileges.");

  script_tag(name:"affected", value:"Kaspersky Anti-Virus versions 17.0.0.x.");

  script_tag(name:"solution", value:"Kaspersky has fixed this issue in the autoupdated patches that
  were issued by December 28. To apply the fixes, please update your products.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40988");
  script_xref(name:"URL", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=989");
  script_xref(name:"URL", value:"https://support.kaspersky.com/vulnerability.aspx?el=12430#281216");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_kaspersky_av_detect.nasl");
  script_mandatory_keys("Kaspersky/products/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:kaspersky_lab:kaspersky_internet_security_2017", "cpe:/a:kaspersky:kaspersky_anti-virus_2017", "cpe:/a:kaspersky:kaspersky_total_security_2017");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

# nb: Installed 2017 version. Currently the version is 17.0.0.611
if(vers =~ "^17\." && version_is_less_equal(version:vers, test_version:"17.0.0.611")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);