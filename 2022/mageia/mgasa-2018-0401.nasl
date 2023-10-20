# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0401");
  script_cve_id("CVE-2018-14938");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-29 02:15:00 +0000 (Sun, 29 Nov 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0401)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0401");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0401.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23538");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/EFRZCT4UN4QXFPROASMGHI2MZ7OWZVZ2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpflow' package(s) announced via the MGASA-2018-0401 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"pdated tcpflow package fixes security vulnerability:

An issue was discovered in wifipcap/wifipcap.cpp in TCPFLOW through
1.5.0-alpha. There is an integer overflow in the function handle_prism
during caplen processing. If the caplen is less than 144, one can cause
an integer overflow in the function handle_80211, which will result in
an out-of-bounds read and may allow access to sensitive memory or a
denial of service (CVE-2018-14938).");

  script_tag(name:"affected", value:"'tcpflow' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"tcpflow", rpm:"tcpflow~1.5.0~1.mga6", rls:"MAGEIA6"))) {
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
