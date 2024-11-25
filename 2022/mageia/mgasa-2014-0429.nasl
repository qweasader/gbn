# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0429");
  script_cve_id("CVE-2014-3686");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0429)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0429");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0429.html");
  script_xref(name:"URL", value:"http://w1.fi/security/2014-1/wpacli-action-scripts.txt");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14262");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hostapd, wpa_supplicant' package(s) announced via the MGASA-2014-0429 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in the mechanism wpa_cli and hostapd_cli use
for executing action scripts. An unsanitized string received from a
remote device can be passed to a system() call resulting in arbitrary
command execution under the privileges of the wpa_cli/hostapd_cli
process (which may be root in common use cases) (CVE-2014-3686).

Using the Mageia wpa_supplicant package, systems are exposed to the
vulnerability if operating as a WPS registrar.

The Mageia hostapd package was not vulnerable with the configuration with
which it was built, but if a sysadmin had rebuilt it with WPS enabled, it
would be vulnerable.");

  script_tag(name:"affected", value:"'hostapd, wpa_supplicant' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"hostapd", rpm:"hostapd~1.1~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~1.1~4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-gui", rpm:"wpa_supplicant-gui~1.1~4.1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"hostapd", rpm:"hostapd~2.0~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.0~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-gui", rpm:"wpa_supplicant-gui~2.0~2.1.mga4", rls:"MAGEIA4"))) {
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
