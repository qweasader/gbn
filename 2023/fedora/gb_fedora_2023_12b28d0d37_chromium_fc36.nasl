# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827679");
  script_version("2023-05-12T10:50:26+0000");
  script_cve_id("CVE-2023-2459", "CVE-2023-2460", "CVE-2023-2461", "CVE-2023-2462", "CVE-2023-2463", "CVE-2023-2464", "CVE-2023-2465", "CVE-2023-2466", "CVE-2023-2467", "CVE-2023-2468");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-05-12 10:50:26 +0000 (Fri, 12 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-10 01:07:52 +0000 (Wed, 10 May 2023)");
  script_name("Fedora: Security Advisory for chromium (FEDORA-2023-12b28d0d37)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-12b28d0d37");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U3V6GPGMY6ZWVWPECMQGGOKQVATXJ5BA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2023-12b28d0d37 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~113.0.5672.63~1.fc36", rls:"FC36"))) {
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