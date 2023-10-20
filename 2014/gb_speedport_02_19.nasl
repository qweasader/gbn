# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:t-com:speedport';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105901");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2014-9727");
  script_name("Speedport DSL-Router Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.telekom.com/verantwortung/sicherheit/216230");
  script_xref(name:"URL", value:"http://www.heise.de/newsticker/meldung/Fritzbox-Luecke-Vier-Speedport-Modelle-der-Telekom-betroffen-2118595.html");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-14 12:11:28 +0700 (Fri, 14 Mar 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_speedport_detect.nasl");
  script_mandatory_keys("speedport/model", "speedport/firmware_version");

  script_tag(name:"vuldetect", value:"Check the firmware version.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references section
  for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Speedport DSL-Router is prone to multiple vulnerabilities");

  script_tag(name:"affected", value:"See the list at the linked vendor page.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!model = get_kb_item("speedport/model")) {
  exit(0);
}

if (!fw_version =  get_kb_item("speedport/firmware_version")) {
  exit(0);
}

fixes = make_array(
                   "W 503V", "66.04.79",
                   "W 721V", "64.04.75",
                   "W 722V", "80.04.79",
                   "W 920V", "65.04.79"
                  );

if (!fixes[model]) {
  exit(99);
}

patch = fixes[model];

if (version_is_less(version:fw_version, test_version:patch)) {
  report = 'Model: ' + model + '\nInstalled Firmware: ' + fw_version + '\nFixed Firmware:     ' + patch + '\n';
  security_message(port:0, data:report);
  exit(0);
}
