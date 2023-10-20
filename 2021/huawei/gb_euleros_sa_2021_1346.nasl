# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1346");
  script_cve_id("CVE-2019-10146", "CVE-2019-10179", "CVE-2019-11358", "CVE-2020-1721");
  script_tag(name:"creation_date", value:"2021-02-22 08:39:59 +0000 (Mon, 22 Feb 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-10 20:16:00 +0000 (Mon, 10 May 2021)");

  script_name("Huawei EulerOS: Security Advisory for pki-core (EulerOS-SA-2021-1346)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1346");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1346");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'pki-core' package(s) announced via the EulerOS-SA-2021-1346 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Key Recovery Authority (KRA) Agent Service where it did not properly sanitize the recovery ID during a key recovery request, enabling a Reflected Cross-Site Scripting (XSS) vulnerability. An attacker could trick an authenticated victim into executing specially crafted Javascript code.(CVE-2020-1721)

A Reflected Cross Site Scripting flaw was found in all pki-core 10.x.x versions module from the pki-core server due to the CA Agent Service not properly sanitizing the certificate request page. An attacker could inject a specially crafted value that will be executed on the victim's browser.(CVE-2019-10146)

A vulnerability was found in all pki-core 10.x.x versions, where the Key Recovery Authority (KRA) Agent Service did not properly sanitize recovery request search page, enabling a Reflected Cross Site Scripting (XSS) vulnerability. An attacker could trick an authenticated victim into executing specially crafted Javascript code.(CVE-2019-10179)

jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution. If an unsanitized source object contained an enumerable __proto__ property, it could extend the native Object.prototype.(CVE-2019-11358)");

  script_tag(name:"affected", value:"'pki-core' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"pki-base", rpm:"pki-base~10.2.5~6.h2", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-ca", rpm:"pki-ca~10.2.5~6.h2", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-kra", rpm:"pki-kra~10.2.5~6.h2", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-server", rpm:"pki-server~10.2.5~6.h2", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-symkey", rpm:"pki-symkey~10.2.5~6.h2", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-tools", rpm:"pki-tools~10.2.5~6.h2", rls:"EULEROS-2.0SP2"))) {
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
