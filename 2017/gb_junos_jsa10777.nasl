# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106753");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-13 08:24:49 +0200 (Thu, 13 Apr 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-2312");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper Networks Junos OS LDP DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected");

  script_tag(name:"summary", value:"Junos OS is prone to a denial of service (DoS) vulnerability. when receiving crafted
LDP packets.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"A specific LDP packet destined to the RE (Routing Engine) will consume a
small amount of the memory allocated for the rpd process. Over time, repeatedly receiving this type of LDP
packet(s) will cause the memory to exhaust and the rpd process to crash and restart. It is not possible to free
up the memory that has been consumed without restarting the rpd process. This issue affects Junos OS based
devices with either IPv4 or IPv6 LDP enabled via the [protocols ldp] configuration. The interface on which the
packet arrives needs to have LDP enabled.");

  script_tag(name:"impact", value:"An attacker may cause a denial of service condition.");

  script_tag(name:"affected", value:"Junos OS 13.3, 14.1, 14.2, 15.1 and 16.1");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. As a
workaround use access lists or firewall filters to limit access to the device via LDP only from trusted networks
or hosts, or enable MD5 authentication on all authorized LDP sessions.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10777");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^13") {
  if (revcomp(a: version, b: "13.3R10") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.3R10");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^14") {
  if (revcomp(a: version, b: "14.1R8") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.1R8");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "14.2R8") < 0) &&
           (revcomp(a: version, b: "14.2") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.2R8");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^15") {
  if ((revcomp(a: version, b: "15.1F7") < 0) &&
      (revcomp(a: version, b: "15.1F") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1F7");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1R5") < 0) &&
           (revcomp(a: version, b: "15.1R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1R5");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1X49-D70") < 0) &&
           (revcomp(a: version, b: "15.1X49") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1X49-D70");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1X53-D63") < 0) &&
           (revcomp(a: version, b: "15.1X53") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1X53-D63");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^16") {
  if (revcomp(a: version, b: "16.1R2") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "16.1R2");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
