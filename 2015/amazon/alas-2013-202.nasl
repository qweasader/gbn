# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120025");
  script_cve_id("CVE-2013-3571");
  script_tag(name:"creation_date", value:"2015-09-08 11:15:35 +0000 (Tue, 08 Sep 2015)");
  script_version("2023-03-23T10:19:31+0000");
  script_tag(name:"last_modification", value:"2023-03-23 10:19:31 +0000 (Thu, 23 Mar 2023)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2013-202)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2013-202");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2013-202.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'socat' package(s) announced via the ALAS-2013-202 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"socat 1.2.0.0 before 1.7.2.2 and 2.0.0-b1 before 2.0.0-b6, when used for a listen type address and the fork option is enabled, allows remote attackers to cause a denial of service (file descriptor consumption) via multiple requests that are refused based on the (1) sourceport, (2) lowport, (3) range, or (4) tcpwrap restrictions.");

  script_tag(name:"affected", value:"'socat' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"socat", rpm:"socat~1.7.2.2~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"socat-debuginfo", rpm:"socat-debuginfo~1.7.2.2~1.8.amzn1", rls:"AMAZON"))) {
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
