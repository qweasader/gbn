# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0195");
  script_cve_id("CVE-2020-11810");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-14 02:31:40 +0000 (Thu, 14 May 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0195)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0195");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0195.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26558");
  script_xref(name:"URL", value:"https://community.openvpn.net/openvpn/wiki/ChangesInOpenvpn24");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/F6UXS4WUVAGMXRRBWQNUHMT5JZYYW4KW/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvpn' package(s) announced via the MGASA-2020-0195 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated openvpn packages fix security vulnerability:

An issue was discovered in OpenVPN 2.4.x before 2.4.9. An attacker can
inject a data channel v2 (P_DATA_V2) packet using a victim's peer-id.
Normally such packets are dropped, but if this packet arrives before the
data channel crypto parameters have been initialized, the victim's
connection will be dropped. This requires careful timing due to the small
time window (usually within a few seconds) between the victim client
connection starting and the server PUSH_REPLY response back to the client.
This attack will only work if Negotiable Cipher Parameters (NCP) is in
use (CVE-2020-11810).

The openvpn package has been updated to version 2.4.9, fixing the issue
and other bugs. See the upstream release notes for details.");

  script_tag(name:"affected", value:"'openvpn' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64openvpn-devel", rpm:"lib64openvpn-devel~2.4.9~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenvpn-devel", rpm:"libopenvpn-devel~2.4.9~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvpn", rpm:"openvpn~2.4.9~1.mga7", rls:"MAGEIA7"))) {
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
