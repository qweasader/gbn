# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885175");
  script_cve_id("CVE-2023-41335", "CVE-2023-42453", "CVE-2023-45129");
  script_tag(name:"creation_date", value:"2023-11-05 02:20:18 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-17 20:18:56 +0000 (Tue, 17 Oct 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-4d4c73a8f0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-4d4c73a8f0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-4d4c73a8f0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'matrix-synapse' package(s) announced via the FEDORA-2023-4d4c73a8f0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to v1.94.0 (CVE-2023-45129)

----

Update to v1.93.0 (CVE-2023-41335, CVE-2023-42453)");

  script_tag(name:"affected", value:"'matrix-synapse' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+cache_memory", rpm:"matrix-synapse+cache_memory~1.94.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+jwt", rpm:"matrix-synapse+jwt~1.94.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+matrix-synapse-ldap3", rpm:"matrix-synapse+matrix-synapse-ldap3~1.94.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+oidc", rpm:"matrix-synapse+oidc~1.94.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+postgres", rpm:"matrix-synapse+postgres~1.94.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+saml2", rpm:"matrix-synapse+saml2~1.94.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+systemd", rpm:"matrix-synapse+systemd~1.94.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+url_preview", rpm:"matrix-synapse+url_preview~1.94.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse+user-search", rpm:"matrix-synapse+user-search~1.94.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse", rpm:"matrix-synapse~1.94.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse-debuginfo", rpm:"matrix-synapse-debuginfo~1.94.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse-debugsource", rpm:"matrix-synapse-debugsource~1.94.0~2.fc39", rls:"FC39"))) {
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
