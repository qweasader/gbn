# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0466");
  script_cve_id("CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0466)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0466");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0466.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14205");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2014-007.html");
  script_xref(name:"URL", value:"https://www.kde.org/info/security/advisory-20140923-1.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdenetwork4' package(s) announced via the MGASA-2014-0466 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A malicious VNC client can trigger multiple DoS conditions on the VNC server
by advertising a large screen size, ClientCutText message length and/or a zero
scaling factor parameter (CVE-2014-6053, CVE-2014-6054).

A malicious VNC client can trigger multiple stack-based buffer overflows by
passing a long file and directory names and/or attributes (FileTime) when
using the file transfer message feature (CVE-2014-6055).

The krfb package is built with a bundled copy of libvncserver.");

  script_tag(name:"affected", value:"'kdenetwork4' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"kde4-filesharing", rpm:"kde4-filesharing~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdenetwork-strigi-analyzers", rpm:"kdenetwork-strigi-analyzers~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdenetwork4", rpm:"kdenetwork4~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdenetwork4-devel", rpm:"kdenetwork4-devel~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdnssd", rpm:"kdnssd~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kget", rpm:"kget~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kget-handbook", rpm:"kget-handbook~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kopete", rpm:"kopete~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kopete-handbook", rpm:"kopete-handbook~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kopete-latex", rpm:"kopete-latex~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kppp", rpm:"kppp~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kppp-handbook", rpm:"kppp-handbook~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kppp-provider", rpm:"kppp-provider~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krdc", rpm:"krdc~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krdc-handbook", rpm:"krdc-handbook~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krfb", rpm:"krfb~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krfb-handbook", rpm:"krfb-handbook~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kgetcore4", rpm:"lib64kgetcore4~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopete4", rpm:"lib64kopete4~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopete_oscar4", rpm:"lib64kopete_oscar4~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopete_videodevice4", rpm:"lib64kopete_videodevice4~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopeteaddaccountwizard1", rpm:"lib64kopeteaddaccountwizard1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopetechatwindow_shared1", rpm:"lib64kopetechatwindow_shared1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopetecontactlist1", rpm:"lib64kopetecontactlist1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopeteidentity1", rpm:"lib64kopeteidentity1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopeteprivacy1", rpm:"lib64kopeteprivacy1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kopetestatusmenu1", rpm:"lib64kopetestatusmenu1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krdccore4", rpm:"lib64krdccore4~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krfbprivate4", rpm:"lib64krfbprivate4~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kyahoo1", rpm:"lib64kyahoo1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64oscar1", rpm:"lib64oscar1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkgetcore4", rpm:"libkgetcore4~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopete4", rpm:"libkopete4~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopete_oscar4", rpm:"libkopete_oscar4~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopete_videodevice4", rpm:"libkopete_videodevice4~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopeteaddaccountwizard1", rpm:"libkopeteaddaccountwizard1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopetechatwindow_shared1", rpm:"libkopetechatwindow_shared1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopetecontactlist1", rpm:"libkopetecontactlist1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopeteidentity1", rpm:"libkopeteidentity1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopeteprivacy1", rpm:"libkopeteprivacy1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkopetestatusmenu1", rpm:"libkopetestatusmenu1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrdccore4", rpm:"libkrdccore4~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrfbprivate4", rpm:"libkrfbprivate4~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkyahoo1", rpm:"libkyahoo1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboscar1", rpm:"liboscar1~4.10.5~1.3.mga3", rls:"MAGEIA3"))) {
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
