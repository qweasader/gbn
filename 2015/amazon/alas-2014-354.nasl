# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120315");
  script_cve_id("CVE-2013-7041", "CVE-2014-2583");
  script_tag(name:"creation_date", value:"2015-09-08 11:23:23 +0000 (Tue, 08 Sep 2015)");
  script_version("2023-10-06T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-354)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-354");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-354.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the ALAS-2014-354 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple directory traversal vulnerabilities in pam_timestamp.c in the pam_timestamp module for Linux-PAM (aka pam) 1.1.8 allow local users to create arbitrary files or possibly bypass authentication via a .. (dot dot) in the (1) PAM_RUSER value to the get_ruser function or (2) PAM_TTY value to the check_tty function, which is used by the format_timestamp_name function.

The pam_userdb module for Pam uses a case-insensitive method to compare hashed passwords, which makes it easier for attackers to guess the password via a brute force attack.");

  script_tag(name:"affected", value:"'pam' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"pam", rpm:"pam~1.1.8~9.29.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-debuginfo", rpm:"pam-debuginfo~1.1.8~9.29.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-devel", rpm:"pam-devel~1.1.8~9.29.amzn1", rls:"AMAZON"))) {
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
