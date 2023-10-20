# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0409");
  script_cve_id("CVE-2014-1829", "CVE-2014-1830");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0409)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0409");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0409.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14130");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1046626");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1144907");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-requests' package(s) announced via the MGASA-2014-0409 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-requests packages fix security vulnerability:

Python-requests was found to have a vulnerability, where the attacker can
retrieve the passwords from ~/.netrc file through redirect requests, if the
user has their passwords stored in the ~/.netrc file (CVE-2014-1829).

It was discovered that the python-requests Proxy-Authorization header was
never re-evaluated when a redirect occurs. The Proxy-Authorization header
was sent to any new proxy or non-proxy destination as redirected
(CVE-2014-1830).");

  script_tag(name:"affected", value:"'python-requests' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"python-requests", rpm:"python-requests~2.3.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-requests", rpm:"python3-requests~2.3.0~1.mga4", rls:"MAGEIA4"))) {
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
