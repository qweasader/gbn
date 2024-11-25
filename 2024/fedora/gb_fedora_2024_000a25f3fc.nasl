# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886743");
  script_cve_id("CVE-2024-27306");
  script_tag(name:"creation_date", value:"2024-05-27 10:44:43 +0000 (Mon, 27 May 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-000a25f3fc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-000a25f3fc");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-000a25f3fc");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275989");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275991");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/releases/tag/v3.9.4");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/releases/tag/v3.9.5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-aiohttp, python-openapi-core' package(s) announced via the FEDORA-2024-000a25f3fc advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security update for CVE-2024-27306

[link moved to references]

[link moved to references]");

  script_tag(name:"affected", value:"'python-aiohttp, python-openapi-core' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"python-aiohttp", rpm:"python-aiohttp~3.9.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-aiohttp-debugsource", rpm:"python-aiohttp-debugsource~3.9.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-openapi-core", rpm:"python-openapi-core~0.19.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp+speedups", rpm:"python3-aiohttp+speedups~3.9.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp", rpm:"python3-aiohttp~3.9.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp-debuginfo", rpm:"python3-aiohttp-debuginfo~3.9.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+aiohttp", rpm:"python3-openapi-core+aiohttp~0.19.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+django", rpm:"python3-openapi-core+django~0.19.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+falcon", rpm:"python3-openapi-core+falcon~0.19.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+fastapi", rpm:"python3-openapi-core+fastapi~0.19.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+flask", rpm:"python3-openapi-core+flask~0.19.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+requests", rpm:"python3-openapi-core+requests~0.19.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+starlette", rpm:"python3-openapi-core+starlette~0.19.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core", rpm:"python3-openapi-core~0.19.1~3.fc40", rls:"FC40"))) {
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
