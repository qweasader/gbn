# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0079");
  script_cve_id("CVE-2017-6410");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-03 14:47:13 +0000 (Fri, 03 Mar 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0079)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0079");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0079.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20403");
  script_xref(name:"URL", value:"https://www.kde.org/info/security/advisory-20170228-1.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdelibs4' package(s) announced via the MGASA-2017-0079 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Using a malicious PAC file, and then using exfiltration methods in the PAC
function FindProxyForURL() enables the attacker to expose full https URLs.

This is a security issue since https URLs may contain sensitive
information in the URL authentication part (user:password@host), and in
the path and the query (e.g. access tokens).

This attack can be carried out remotely (over the LAN) since proxy
settings allow 'Detect Proxy Configuration Automatically'.
This setting uses WPAD to retrieve the PAC file, and an attacker who has
access to the victim's LAN can interfere with the WPAD protocols
(DHCP/DNS+HTTP) and inject his/her own malicious PAC instead of the
legitimate one");

  script_tag(name:"affected", value:"'kdelibs4' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4", rpm:"kdelibs4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-core", rpm:"kdelibs4-core~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-devel", rpm:"kdelibs4-devel~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-handbooks", rpm:"kdelibs4-handbooks~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcmutils4", rpm:"lib64kcmutils4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kde3support4", rpm:"lib64kde3support4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdeclarative5", rpm:"lib64kdeclarative5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdecore5", rpm:"lib64kdecore5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdefakes5", rpm:"lib64kdefakes5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdesu5", rpm:"lib64kdesu5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdeui5", rpm:"lib64kdeui5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdewebkit5", rpm:"lib64kdewebkit5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdnssd4", rpm:"lib64kdnssd4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kemoticons4", rpm:"lib64kemoticons4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kfile4", rpm:"lib64kfile4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64khtml5", rpm:"lib64khtml5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kidletime4", rpm:"lib64kidletime4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kimproxy4", rpm:"lib64kimproxy4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kio5", rpm:"lib64kio5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kjs4", rpm:"lib64kjs4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kjsapi4", rpm:"lib64kjsapi4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kjsembed4", rpm:"lib64kjsembed4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kmediaplayer4", rpm:"lib64kmediaplayer4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64knewstuff2_4", rpm:"lib64knewstuff2_4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64knewstuff3_4", rpm:"lib64knewstuff3_4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64knotifyconfig4", rpm:"lib64knotifyconfig4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kntlm4", rpm:"lib64kntlm4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kparts4", rpm:"lib64kparts4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kprintutils4", rpm:"lib64kprintutils4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kpty4", rpm:"lib64kpty4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krosscore4", rpm:"lib64krosscore4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krossui4", rpm:"lib64krossui4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ktexteditor4", rpm:"lib64ktexteditor4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kunitconversion4", rpm:"lib64kunitconversion4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kunittest4", rpm:"lib64kunittest4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kutils4", rpm:"lib64kutils4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nepomuk4", rpm:"lib64nepomuk4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nepomukquery4", rpm:"lib64nepomukquery4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nepomukutils4", rpm:"lib64nepomukutils4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasma3", rpm:"lib64plasma3~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64solid4", rpm:"lib64solid4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64threadweaver4", rpm:"lib64threadweaver4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcmutils4", rpm:"libkcmutils4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkde3support4", rpm:"libkde3support4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeclarative5", rpm:"libkdeclarative5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdecore5", rpm:"libkdecore5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdefakes5", rpm:"libkdefakes5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdesu5", rpm:"libkdesu5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeui5", rpm:"libkdeui5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdewebkit5", rpm:"libkdewebkit5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdnssd4", rpm:"libkdnssd4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkemoticons4", rpm:"libkemoticons4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkfile4", rpm:"libkfile4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkhtml5", rpm:"libkhtml5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkidletime4", rpm:"libkidletime4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkimproxy4", rpm:"libkimproxy4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkio5", rpm:"libkio5~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkjs4", rpm:"libkjs4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkjsapi4", rpm:"libkjsapi4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkjsembed4", rpm:"libkjsembed4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmediaplayer4", rpm:"libkmediaplayer4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libknewstuff2_4", rpm:"libknewstuff2_4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libknewstuff3_4", rpm:"libknewstuff3_4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libknotifyconfig4", rpm:"libknotifyconfig4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkntlm4", rpm:"libkntlm4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkparts4", rpm:"libkparts4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkprintutils4", rpm:"libkprintutils4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkpty4", rpm:"libkpty4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrosscore4", rpm:"libkrosscore4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrossui4", rpm:"libkrossui4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libktexteditor4", rpm:"libktexteditor4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkunitconversion4", rpm:"libkunitconversion4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkunittest4", rpm:"libkunittest4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkutils4", rpm:"libkutils4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnepomuk4", rpm:"libnepomuk4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnepomukquery4", rpm:"libnepomukquery4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnepomukutils4", rpm:"libnepomukutils4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasma3", rpm:"libplasma3~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolid4", rpm:"libsolid4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libthreadweaver4", rpm:"libthreadweaver4~4.14.30~1.mga5", rls:"MAGEIA5"))) {
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
