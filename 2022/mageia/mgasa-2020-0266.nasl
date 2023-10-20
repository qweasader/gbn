# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0266");
  script_cve_id("CVE-2019-1010142", "CVE-2019-1010262");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-01 16:39:00 +0000 (Wed, 01 Mar 2023)");

  script_name("Mageia: Security Advisory (MGASA-2020-0266)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0266");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0266.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25954");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/GICTAGUAV4OGIAPKKWXSEVIXU7DZEJ2V/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'scapy' package(s) announced via the MGASA-2020-0266 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated scapy packages fix security vulnerabilities:

A vulnerability was found in scapy 2.4.0 and earlier is affected by:
Denial of Services. The impact is: busy loop forever. The component
is:
_RADIUSAttrPacketListField class. The attack vector is: a packet sent
over the network or in a pcap (CVE-2019-1010262).

scapy 2.4.0 is affected by: Denial of Service. The impact is: infinite
loop, resource consumption and program unresponsive. The component is:
_RADIUSAttrPacketListField.getfield(self..). The attack vector is: over
the network or in a pcap. both work (CVE-2019-1010142).");

  script_tag(name:"affected", value:"'scapy' package(s) on Mageia 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"python2-scapy", rpm:"python2-scapy~2.4.0~3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-scapy", rpm:"python3-scapy~2.4.0~3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scapy", rpm:"scapy~2.4.0~3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
