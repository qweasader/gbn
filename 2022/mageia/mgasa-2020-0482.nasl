# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0482");
  script_cve_id("CVE-2020-8231", "CVE-2020-8284", "CVE-2020-8285", "CVE-2020-8286");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0482)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0482");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0482.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27154");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/CVE-2020-8231.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4466-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/Q7JHSXTQ7EUHJPYL333CB3OBCKHA5FQC/");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2020-8284.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2020-8285.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2020-8286.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4665-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/NZUVSQHN2ESHMJXNQ2Z7T2EELBB5HJXG/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the MGASA-2020-0482 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Due to use of a dangling pointer, libcurl 7.29.0 through 7.71.1 can use the
wrong connection when sending data. (CVE-2020-8231).

A malicious server can use the FTP PASV response to trick curl 7.73.0 and
earlier into connecting back to a given IP address and port, and this way
potentially make curl extract information about services that are otherwise
private and not disclosed, for example doing port scanning and service banner
extractions. (CVE-2020-8284).

curl 7.21.0 to and including 7.73.0 is vulnerable to uncontrolled recursion
due to a stack overflow issue in FTP wildcard match parsing. (CVE-2020-8285).

curl 7.41.0 through 7.73.0 is vulnerable to an improper check for certificate
revocation due to insufficient verification of the OCSP response.
(CVE-2020-8286).");

  script_tag(name:"affected", value:"'curl' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.71.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-examples", rpm:"curl-examples~7.71.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl-devel", rpm:"lib64curl-devel~7.71.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl4", rpm:"lib64curl4~7.71.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.71.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.71.0~1.1.mga7", rls:"MAGEIA7"))) {
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
