# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0428");
  script_cve_id("CVE-2014-3188", "CVE-2014-3189", "CVE-2014-3190", "CVE-2014-3191", "CVE-2014-3192", "CVE-2014-3193", "CVE-2014-3194", "CVE-2014-3195", "CVE-2014-3197", "CVE-2014-3198", "CVE-2014-3199", "CVE-2014-3200");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0428)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0428");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0428.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14258");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2014/10/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2014/10/stable-channel-update_14.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2014-1626.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2014-0428 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Chromium to crash or,
potentially, execute arbitrary code with the privileges of the user running
Chromium (CVE-2014-3188, CVE-2014-3189, CVE-2014-3190, CVE-2014-3191,
CVE-2014-3192, CVE-2014-3193, CVE-2014-3194, CVE-2014-3199, CVE-2014-3200).

Several information leak flaws were found in the processing of malformed
web content. A web page containing malicious content could cause Chromium
to disclose potentially sensitive information (CVE-2014-3195,
CVE-2014-3197, CVE-2014-3198).");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~38.0.2125.104~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~38.0.2125.104~1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~38.0.2125.104~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~38.0.2125.104~1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~38.0.2125.104~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~38.0.2125.104~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~38.0.2125.104~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~38.0.2125.104~1.mga4.tainted", rls:"MAGEIA4"))) {
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
