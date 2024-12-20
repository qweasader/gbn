# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103959");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-11-29 12:26:17 +0700 (Fri, 29 Nov 2013)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2013-0149");

  script_name("Juniper Networks Junos OS OSPF Protocol Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected", "juniper/junos/build");

  script_tag(name:"summary", value:"A vulnerability in the OSPF protocol allows a remote attacker to
insert, update or delete routes in the OSPF database.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been discovered in the OSPF (Open Shortest
Path First) protocol that allows a remote attacker to insert, update or delete routes in the OSPF database.");

  script_tag(name:"impact", value:"A remote attacker might re-route traffic, compromise the
confidentially of data or cunduct a DoS attack by dropping all traffic.");

  script_tag(name:"affected", value:"Platforms running Junos OS before versions 13.1R3,
13.2X50-D10, 12.3R3, 12.2R5, 12.1R7, 12.1X45-D10, 12.1X44-D15, 11.4R8 and 10.4R15");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. Use
MD5 authentication when configuring OSPF. MD5 authentication completely mitigates this issue.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10582");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/229804");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61566");

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

if (revcomp(a:build2check, b:"20130725") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"10.4R15") < 0) {
  security_message(port:0, data:desc);
  exit(0);
}

if (version =~ "^11") {
  if (revcomp(a:version, b:"11.4R8") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (version =~ "^12") {
  if (revcomp(a:version, b:"12.1R7") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.1X44-D15") < 0) &&
             (revcomp(a:version, b:"12.1X44") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  } else if ((revcomp(a:version, b:"12.1X45-D10") < 0) &&
             (revcomp(a:version, b:"12.1X45") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  } else if ((revcomp(a:version, b:"12.2R5") < 0) &&
             (revcomp(a:version, b:"12.2") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  } else if ((revcomp(a:version, b:"12.3R3") < 0) &&
             (revcomp(a:version, b:"12.3") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  }
}

if (version =~ "^13") {
  if (revcomp(a:version, b:"13.1R3") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"13.2X50-D10") < 0) &&
             (revcomp(a:version, b:"13.2X50") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  }
}

exit(99);
