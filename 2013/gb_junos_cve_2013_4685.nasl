# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103961");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-09 22:07:11 +0700 (Mon, 09 Dec 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2013-4685");

  script_name("Juniper Networks Junos OS Buffer Overflow when Processing HTTP Messages");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected", "juniper/junos/build");

  script_tag(name:"summary", value:"Buffer Overflow in flowd when processing HTTP protocol messages");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow vulnerability affects the flowd process while
processing HTTP protocol messages. This issue can be triggered when the SRX Series device is acting as a
Unified Access Control (UAC) enforcer in a UAC network with Captive Portal enabled.");

  script_tag(name:"impact", value:"A remote attacker may execute arbitrary code using crafted HTTP
requests.");

  script_tag(name:"affected", value:"Junos OS on SRX Series running 10.4, 11.4 12.1, or 12.1X44.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10574");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61125");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("juniper/junos/build");
if (!build)
  exit(0);

desc += "Version/Build-Date:
" + version + " / " + build;

build2check = str_replace(string:build, find:"-", replace:"");

if (revcomp(a:build2check, b:"20130620") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"10.4R15") < 0) {
  security_message(port:0, data:desc);
  exit(0);
}

if (version =~ "^10\.4S") {
  if (revcomp(a:version, b:"10.4S14") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (version =~ "^11") {
  if (revcomp(a:version, b:"11.4R7") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (version =~ "^12") {
  if (revcomp(a:version, b:"12.1R6") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.1X44-D15") < 0) &&
             (revcomp(a:version, b:"12.1X") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

exit(99);
