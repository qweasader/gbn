# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0423");
  script_cve_id("CVE-2016-10002", "CVE-2016-10003");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 03:03:55 +0000 (Fri, 02 Feb 2024)");

  script_name("Mageia: Security Advisory (MGASA-2016-0423)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0423");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0423.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/12/18/1");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2016_10.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2016_11.txt");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19970");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the MGASA-2016-0423 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Incorrect processing of responses to If-None-Modified HTTP conditional
requests leads to client-specific Cookie data being leaked to other
clients. Attack requests can easily be crafted by a client to probe a
cache for this information (CVE-2016-10002).

Incorrect HTTP Request header comparison results in Collapsed Forwarding
feature mistakenly identifying some private responses as being suitable
for delivery to multiple clients (CVE-2016-10003).");

  script_tag(name:"affected", value:"'squid' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~3.5.23~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~3.5.23~1.mga5", rls:"MAGEIA5"))) {
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
