# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0066");
  script_cve_id("CVE-2016-10195", "CVE-2016-10196", "CVE-2016-10197");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-21 14:29:54 +0000 (Tue, 21 Mar 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0066)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0066");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0066.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/02/02/7");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/01/31/17");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20233");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libevent' package(s) announced via the MGASA-2017-0066 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"* The DNS code of Libevent contains an OOB read which can trigger a crash
 (CVE-2016-10197)
* The libevent evutil_parse_sockaddr_port() contains a buffer overflow
 which can cause a segmentation fault (CVE-2016-10196)
* The name_parse() function in libevent's DNS code is vulnerable to a
 buffer overread (CVE-2016-10195)");

  script_tag(name:"affected", value:"'libevent' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64event-devel", rpm:"lib64event-devel~2.0.22~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64event5", rpm:"lib64event5~2.0.22~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevent", rpm:"libevent~2.0.22~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevent-devel", rpm:"libevent-devel~2.0.22~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevent5", rpm:"libevent5~2.0.22~1.1.mga5", rls:"MAGEIA5"))) {
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
