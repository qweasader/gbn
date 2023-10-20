# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:manageengine:password_manager_pro";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805715");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-07 15:16:06 +0530 (Tue, 07 Jul 2015)");
  script_name("ManageEngine Password Manager Pro SQL injection Vulnerability");

  script_tag(name:"summary", value:"ManageEngine Password Manager Pro is prone to a SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to error while escaping the
  operator when more than one condition is specified in the advanced search.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"ManageEngine Password Manager
  Pro 8.1 Build 8100 and below.");

  script_tag(name:"solution", value:"Upgrade to 8.1 Build 8101 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132511");
  script_xref(name:"URL", value:"https://www.manageengine.com/products/passwordmanagerpro/release-notes.html");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_pass_mang_pro_detect.nasl");
  script_mandatory_keys("ManageEngine/Password_Manager/installed");
  script_require_ports("Services/www", 7272);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!mePort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!meVer = get_app_version(cpe:CPE, port:mePort)){
  exit(0);
}

if(version_is_less(version:meVer, test_version:"8101"))
{
  report = 'Installed Version: ' + meVer + '\n' +
           'Fixed Version:     8.1 (Build 8101)\n';
  security_message(data:report, port:mePort);
  exit(0);
}
