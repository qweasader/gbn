# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0054");
  script_cve_id("CVE-2017-1000254", "CVE-2017-1000257", "CVE-2017-8816", "CVE-2017-8817");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-15 16:20:57 +0000 (Fri, 15 Dec 2017)");

  script_name("Mageia: Security Advisory (MGASA-2018-0054)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0054");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0054.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21819");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_2017-12e7.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_2017-ae72.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20171004.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20171023.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the MGASA-2018-0054 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libcurl contains a buffer overrun flaw in the NTLM authentication code
(CVE-2017-8816).

libcurl contains a read out of bounds flaw in the FTP wildcard function
(CVE-2017-8817).

libcurl may read outside of a heap allocated buffer when doing FTP
(CVE-2017-1000254).

libcurl contains a buffer overrun flaw in the IMAP handler
(CVE-2017-1000257).");

  script_tag(name:"affected", value:"'curl' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.54.1~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-examples", rpm:"curl-examples~7.54.1~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl-devel", rpm:"lib64curl-devel~7.54.1~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl4", rpm:"lib64curl4~7.54.1~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.54.1~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.54.1~2.4.mga6", rls:"MAGEIA6"))) {
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
