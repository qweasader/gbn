# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827454");
  script_version("2023-04-13T10:19:10+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-13 10:19:10 +0000 (Thu, 13 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-10 01:06:56 +0000 (Mon, 10 Apr 2023)");
  script_name("Fedora: Security Advisory for seamonkey (FEDORA-2023-a6f685801e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-a6f685801e");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6ILUS673ATZ5EMKRXEJ3OQOU5AUZAEEA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey'
  package(s) announced via the FEDORA-2023-a6f685801e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"SeaMonkey is an all-in-one Internet application suite (previously made
popular by Netscape and Mozilla). It includes an Internet browser,
advanced e-mail, newsgroup and feed client, a calendar, IRC client,
HTML editor and a tool to inspect the DOM for web pages. It is derived
from the application formerly known as Mozilla Application Suite.");

  script_tag(name:"affected", value:"'seamonkey' package(s) on Fedora 36.");

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

  if(!isnull(res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.53.16~1.fc36", rls:"FC36"))) {
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