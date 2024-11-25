# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.10145719297972");
  script_tag(name:"creation_date", value:"2024-11-19 04:08:45 +0000 (Tue, 19 Nov 2024)");
  script_version("2024-11-20T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-20 05:05:31 +0000 (Wed, 20 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-e457192aa2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-e457192aa2");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-e457192aa2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lemonldap-ng' package(s) announced via the FEDORA-2024-e457192aa2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to lemonldap-ng 2.20.1:

- [Security] Adaptative Authentication Rules triggered by 'Refresh my rights'
- [Security] XSS in upgradeSession / forceUpgrade pages
- downloadSamlMetadata missing from packages in 2.20.0
- CDA request for id is not valid
- 'This application is not known' when trying to access a federation application with empty RelayState
- SAML regression in 2.20.0
- Internal error when captcha rule isn't validated");

  script_tag(name:"affected", value:"'lemonldap-ng' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"lemonldap-ng", rpm:"lemonldap-ng~2.20.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lemonldap-ng-common", rpm:"lemonldap-ng-common~2.20.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lemonldap-ng-doc", rpm:"lemonldap-ng-doc~2.20.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lemonldap-ng-fastcgi-server", rpm:"lemonldap-ng-fastcgi-server~2.20.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lemonldap-ng-handler", rpm:"lemonldap-ng-handler~2.20.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lemonldap-ng-manager", rpm:"lemonldap-ng-manager~2.20.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lemonldap-ng-portal", rpm:"lemonldap-ng-portal~2.20.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lemonldap-ng-selinux", rpm:"lemonldap-ng-selinux~2.20.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lemonldap-ng-test", rpm:"lemonldap-ng-test~2.20.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lemonldap-ng-uwsgi-app", rpm:"lemonldap-ng-uwsgi-app~2.20.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Lemonldap-NG-SSOaaS-Apache-Client", rpm:"perl-Lemonldap-NG-SSOaaS-Apache-Client~2.20.1~1.fc40", rls:"FC40"))) {
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
